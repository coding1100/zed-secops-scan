mod preview;
mod repl_menu;

use agent_settings::AgentSettings;
use agent_ui::{AgentPanel, AgentPanelDelegate};
use editor::actions::{
    AddSelectionAbove, AddSelectionBelow, CodeActionSource, DuplicateLineDown, GoToDiagnostic,
    GoToHunk, GoToPreviousDiagnostic, GoToPreviousHunk, MoveLineDown, MoveLineUp, SelectAll,
    SelectLargerSyntaxNode, SelectNext, SelectSmallerSyntaxNode, ToggleCodeActions,
    ToggleDiagnostics, ToggleGoToLine, ToggleInlineDiagnostics,
};
use editor::code_context_menus::{CodeContextMenu, ContextMenuOrigin};
use editor::{Editor, EditorSettings};
use gpui::{
    Action, AnchoredPositionMode, AsyncWindowContext, ClickEvent, Context, Corner, ElementId,
    Entity, EventEmitter, FocusHandle, Focusable, InteractiveElement, ParentElement, Render,
    Styled, Subscription, WeakEntity, Window, anchored, deferred, point,
};
use project::{DisableAiSettings, project_settings::DiagnosticSeverity};
use search::{BufferSearchBar, buffer_search};
use settings::{Settings, SettingsStore};
use ui::{
    ButtonStyle, ContextMenu, ContextMenuEntry, DocumentationSide, IconButton, IconName, IconSize,
    PopoverMenu, PopoverMenuHandle, Tooltip, prelude::*,
};
use vim_mode_setting::{HelixModeSetting, VimModeSetting};
use workspace::item::ItemBufferKind;
use workspace::{
    ToolbarItemEvent, ToolbarItemLocation, ToolbarItemView, Workspace, item::ItemHandle,
    notifications::NotificationId, Toast,
};
use zed_actions::{agent::AddSelectionToThread, assistant::InlineAssist, outline::ToggleOutline};
use zed_actions::agent::SecOpsScan;

const SECOPS_SYSTEM_PROMPT: &str = "You are a security reviewer. Identify vulnerabilities, insecure patterns, secrets, and remediation steps. Keep responses concise and actionable.";
const SECOPS_WARN_BYTES: usize = 200 * 1024;
const SECOPS_HARD_LIMIT_BYTES: usize = 1 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecOpsPayload {
    payload: String,
    truncated: bool,
    original_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SecOpsPayloadError {
    TooLarge { bytes: usize },
}

fn build_secops_payload(contents: &str) -> Result<SecOpsPayload, SecOpsPayloadError> {
    let byte_len = contents.as_bytes().len();
    if byte_len > SECOPS_HARD_LIMIT_BYTES {
        return Err(SecOpsPayloadError::TooLarge { bytes: byte_len });
    }

    if byte_len > SECOPS_WARN_BYTES {
        let truncated_text =
            String::from_utf8_lossy(&contents.as_bytes()[..SECOPS_WARN_BYTES]).into_owned();
        let payload = format!(
            "{SECOPS_SYSTEM_PROMPT}\n\n{truncated_text}\n\n[Content truncated to {SECOPS_WARN_BYTES} bytes]"
        );
        return Ok(SecOpsPayload {
            payload,
            truncated: true,
            original_bytes: byte_len,
        });
    }

    Ok(SecOpsPayload {
        payload: format!("{SECOPS_SYSTEM_PROMPT}\n\n{contents}"),
        truncated: false,
        original_bytes: byte_len,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SecOpsScanError {
    AgentUnavailable,
    NoAgentThread,
    UnsupportedBuffer,
    TooLarge { bytes: usize },
}

impl SecOpsScanError {
    fn message(&self) -> String {
        match self {
            SecOpsScanError::AgentUnavailable => {
                "Open the Agent panel to use SecOps Scan".to_string()
            }
            SecOpsScanError::NoAgentThread => {
                "Create or select an agent thread to use SecOps Scan".to_string()
            }
            SecOpsScanError::UnsupportedBuffer => {
                "SecOps Scan works only for file-backed text buffers".to_string()
            }
            SecOpsScanError::TooLarge { bytes } => format!(
                "File too large for SecOps Scan ({} bytes > {} bytes limit)",
                bytes, SECOPS_HARD_LIMIT_BYTES
            ),
        }
    }
}

fn insert_secops_message(
    workspace: &mut Workspace,
    editor: &Entity<Editor>,
    window: &mut Window,
    cx: &mut Context<Workspace>,
) -> Result<SecOpsPayload, SecOpsScanError> {
    let buffer = editor.read(cx).buffer().clone();
    if !buffer.read(cx).is_singleton() {
        return Err(SecOpsScanError::UnsupportedBuffer);
    }

    let buffer_snapshot = buffer.read(cx).snapshot(cx);
    let contents = buffer_snapshot.text();
    let payload = build_secops_payload(&contents).map_err(|err| match err {
        SecOpsPayloadError::TooLarge { bytes } => SecOpsScanError::TooLarge { bytes },
    })?;

    let Some(agent_delegate) = <dyn AgentPanelDelegate>::try_global(cx) else {
        return Err(SecOpsScanError::AgentUnavailable);
    };

    if workspace.panel::<AgentPanel>(cx).is_some() {
        workspace.focus_panel::<AgentPanel>(window, cx);
    }

    if agent_delegate
        .active_text_thread_editor(workspace, window, cx)
        .is_none()
    {
        if let Some(panel) = workspace.panel::<AgentPanel>(cx) {
            panel.update(cx, |panel, cx| panel.new_text_thread(window, cx));
        }
    }

    let Some(thread_editor) = agent_delegate.active_text_thread_editor(workspace, window, cx) else {
        return Err(SecOpsScanError::NoAgentThread);
    };

    thread_editor.update(cx, |thread_editor, cx| {
        thread_editor.editor().update(cx, |message_editor, cx| {
            let message_snapshot = message_editor.buffer().read(cx).snapshot(cx);
            message_editor.move_to_end(&editor::actions::MoveToEnd, window, cx);
            if !message_snapshot.is_empty() {
                message_editor.insert("\n\n", window, cx);
            }
            message_editor.insert(&payload.payload, window, cx);
        })
    });

    workspace.focus_panel::<AgentPanel>(window, cx);
    Ok(payload)
}

const MAX_CODE_ACTION_MENU_LINES: u32 = 16;

pub struct QuickActionBar {
    _inlay_hints_enabled_subscription: Option<Subscription>,
    _ai_settings_subscription: Subscription,
    active_item: Option<Box<dyn ItemHandle>>,
    buffer_search_bar: Entity<BufferSearchBar>,
    show: bool,
    toggle_selections_handle: PopoverMenuHandle<ContextMenu>,
    toggle_settings_handle: PopoverMenuHandle<ContextMenu>,
    workspace: WeakEntity<Workspace>,
}

impl QuickActionBar {
    pub fn new(
        buffer_search_bar: Entity<BufferSearchBar>,
        workspace: &Workspace,
        cx: &mut Context<Self>,
    ) -> Self {
        let mut was_agent_enabled = AgentSettings::get_global(cx).enabled(cx);
        let mut was_agent_button = AgentSettings::get_global(cx).button;

        let ai_settings_subscription = cx.observe_global::<SettingsStore>(move |_, cx| {
            let agent_settings = AgentSettings::get_global(cx);
            let is_agent_enabled = agent_settings.enabled(cx);

            if was_agent_enabled != is_agent_enabled || was_agent_button != agent_settings.button {
                was_agent_enabled = is_agent_enabled;
                was_agent_button = agent_settings.button;
                cx.notify();
            }
        });

        let mut this = Self {
            _inlay_hints_enabled_subscription: None,
            _ai_settings_subscription: ai_settings_subscription,
            active_item: None,
            buffer_search_bar,
            show: true,
            toggle_selections_handle: Default::default(),
            toggle_settings_handle: Default::default(),
            workspace: workspace.weak_handle(),
        };
        this.apply_settings(cx);
        cx.observe_global::<SettingsStore>(|this, cx| this.apply_settings(cx))
            .detach();
        this
    }

    fn active_editor(&self) -> Option<Entity<Editor>> {
        self.active_item
            .as_ref()
            .and_then(|item| item.downcast::<Editor>())
    }

    fn apply_settings(&mut self, cx: &mut Context<Self>) {
        let new_show = EditorSettings::get_global(cx).toolbar.quick_actions;
        if new_show != self.show {
            self.show = new_show;
            cx.emit(ToolbarItemEvent::ChangeLocation(
                self.get_toolbar_item_location(),
            ));
        }
    }

    fn get_toolbar_item_location(&self) -> ToolbarItemLocation {
        if self.show && self.active_editor().is_some() {
            ToolbarItemLocation::PrimaryRight
        } else {
            ToolbarItemLocation::Hidden
        }
    }
}

impl Render for QuickActionBar {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(editor) = self.active_editor() else {
            return div().id("empty quick action bar");
        };

        let supports_inlay_hints = editor.update(cx, |editor, cx| editor.supports_inlay_hints(cx));
        let editor_value = editor.read(cx);
        let selection_menu_enabled = editor_value.selection_menu_enabled(cx);
        let inlay_hints_enabled = editor_value.inlay_hints_enabled();
        let inline_values_enabled = editor_value.inline_values_enabled();
        let supports_diagnostics = editor_value.mode().is_full();
        let diagnostics_enabled = editor_value.diagnostics_max_severity != DiagnosticSeverity::Off;
        let supports_inline_diagnostics = editor_value.inline_diagnostics_enabled();
        let inline_diagnostics_enabled = editor_value.show_inline_diagnostics();
        let git_blame_inline_enabled = editor_value.git_blame_inline_enabled();
        let show_git_blame_gutter = editor_value.show_git_blame_gutter();
        let auto_signature_help_enabled = editor_value.auto_signature_help_enabled(cx);
        let show_line_numbers = editor_value.line_numbers_enabled(cx);
        let has_edit_prediction_provider = editor_value.edit_prediction_provider().is_some();
        let show_edit_predictions = editor_value.edit_predictions_enabled();
        let edit_predictions_enabled_at_cursor =
            editor_value.edit_predictions_enabled_at_cursor(cx);
        let supports_minimap = editor_value.supports_minimap(cx);
        let minimap_enabled = supports_minimap && editor_value.minimap().is_some();
        let buffer_file_backed = editor_value.buffer().read(cx).is_singleton();
        let has_available_code_actions = editor_value.has_available_code_actions();
        let code_action_enabled = editor_value.code_actions_enabled_for_toolbar(cx);
        let focus_handle = editor_value.focus_handle(cx);

        let search_button = (editor.buffer_kind(cx) == ItemBufferKind::Singleton).then(|| {
            QuickActionBarButton::new(
                "toggle buffer search",
                search::SEARCH_ICON,
                !self.buffer_search_bar.read(cx).is_dismissed(),
                Box::new(buffer_search::Deploy::find()),
                focus_handle.clone(),
                "Buffer Search",
                {
                    let buffer_search_bar = self.buffer_search_bar.clone();
                    move |_, window, cx| {
                        buffer_search_bar.update(cx, |search_bar, cx| {
                            search_bar.toggle(&buffer_search::Deploy::find(), window, cx)
                        });
                    }
                },
            )
        });

        let assistant_button = QuickActionBarButton::new(
            "toggle inline assistant",
            IconName::ZedAssistant,
            false,
            Box::new(InlineAssist::default()),
            focus_handle.clone(),
            "Inline Assist",
            move |_, window, cx| {
                window.dispatch_action(Box::new(InlineAssist::default()), cx);
            },
        );

        let secops_focus = focus_handle.clone();
        let secops_button = buffer_file_backed.then(|| {
            let workspace = self.workspace.clone();
            let editor = editor.clone();
            let toast_id = NotificationId::unique::<SecOpsScan>();
            QuickActionBarButton::new(
                "secops-scan-button",
                IconName::ShieldCheck,
                false,
                Box::new(SecOpsScan),
                secops_focus,
                "SecOps Scan",
                move |_, window, cx| {
                    let workspace = workspace.clone();
                    let toast_id = toast_id.clone();
                    let editor = editor.clone();
                    let _ = workspace.update(cx, |_workspace, cx| {
                        cx.spawn_in(
                            window,
                            move |workspace_weak: WeakEntity<Workspace>, cx: &mut AsyncWindowContext| {
                                let editor = editor.clone();
                                let toast_id = toast_id.clone();
                                let result = if let Some(workspace) = workspace_weak.upgrade() {
                                    workspace.update_in(cx, |workspace, window, cx| {
                                        match insert_secops_message(workspace, &editor, window, cx) {
                                            Ok(payload) => {
                                                if payload.truncated {
                                                    workspace.show_toast(
                                                        Toast::new(
                                                            toast_id.clone(),
                                                            format!(
                                                                "SecOps Scan inserted (truncated to {} KB)",
                                                                SECOPS_WARN_BYTES / 1024
                                                            ),
                                                        )
                                                        .autohide(),
                                                        cx,
                                                    );
                                                } else {
                                                    workspace.show_toast(
                                                        Toast::new(
                                                            toast_id.clone(),
                                                            "SecOps Scan inserted into chat composer",
                                                        )
                                                        .autohide(),
                                                        cx,
                                                    );
                                                }
                                            }
                                            Err(err) => workspace.show_toast(
                                                Toast::new(toast_id.clone(), err.message()).autohide(),
                                                cx,
                                            ),
                                        }
                                    })
                                } else {
                                    Ok(())
                                };
                                async move { result }
                            },
                        )
                        .detach();
                    });
                },
            )
        });

        let code_actions_dropdown = code_action_enabled.then(|| {
            let focus = editor.focus_handle(cx);
            let is_deployed = {
                let menu_ref = editor.read(cx).context_menu().borrow();
                let code_action_menu = menu_ref
                    .as_ref()
                    .filter(|menu| matches!(menu, CodeContextMenu::CodeActions(..)));
                code_action_menu
                    .as_ref()
                    .is_some_and(|menu| matches!(menu.origin(), ContextMenuOrigin::QuickActionBar))
            };
            let code_action_element = is_deployed
                .then(|| {
                    editor.update(cx, |editor, cx| {
                        editor.render_context_menu(MAX_CODE_ACTION_MENU_LINES, window, cx)
                    })
                })
                .flatten();
            v_flex()
                .child(
                    IconButton::new("toggle_code_actions_icon", IconName::BoltOutlined)
                        .icon_size(IconSize::Small)
                        .style(ButtonStyle::Subtle)
                        .disabled(!has_available_code_actions)
                        .toggle_state(is_deployed)
                        .when(!is_deployed, |this| {
                            this.when(has_available_code_actions, |this| {
                                this.tooltip(Tooltip::for_action_title(
                                    "Code Actions",
                                    &ToggleCodeActions::default(),
                                ))
                            })
                            .when(
                                !has_available_code_actions,
                                |this| {
                                    this.tooltip(Tooltip::for_action_title(
                                        "No Code Actions Available",
                                        &ToggleCodeActions::default(),
                                    ))
                                },
                            )
                        })
                        .on_click({
                            let focus = focus;
                            move |_, window, cx| {
                                focus.dispatch_action(
                                    &ToggleCodeActions {
                                        deployed_from: Some(CodeActionSource::QuickActionBar),
                                        quick_launch: false,
                                    },
                                    window,
                                    cx,
                                );
                            }
                        }),
                )
                .children(code_action_element.map(|menu| {
                    deferred(
                        anchored()
                            .position_mode(AnchoredPositionMode::Local)
                            .position(point(px(20.), px(20.)))
                            .anchor(Corner::TopRight)
                            .child(menu),
                    )
                }))
        });

        let editor_selections_dropdown = selection_menu_enabled.then(|| {
            let has_diff_hunks = editor
                .read(cx)
                .buffer()
                .read(cx)
                .snapshot(cx)
                .has_diff_hunks();
            let has_selection = editor.update(cx, |editor, cx| {
                editor.has_non_empty_selection(&editor.display_snapshot(cx))
            });

            let focus = editor.focus_handle(cx);

            let disable_ai = DisableAiSettings::get_global(cx).disable_ai;

            PopoverMenu::new("editor-selections-dropdown")
                .trigger_with_tooltip(
                    IconButton::new("toggle_editor_selections_icon", IconName::CursorIBeam)
                        .icon_size(IconSize::Small)
                        .style(ButtonStyle::Subtle)
                        .toggle_state(self.toggle_selections_handle.is_deployed()),
                    Tooltip::text("Selection Controls"),
                )
                .with_handle(self.toggle_selections_handle.clone())
                .anchor(Corner::TopRight)
                .menu(move |window, cx| {
                    let focus = focus.clone();
                    let menu = ContextMenu::build(window, cx, move |menu, _, _| {
                        menu.context(focus.clone())
                            .action("Select All", Box::new(SelectAll))
                            .action(
                                "Select Next Occurrence",
                                Box::new(SelectNext {
                                    replace_newest: false,
                                }),
                            )
                            .action("Expand Selection", Box::new(SelectLargerSyntaxNode))
                            .action("Shrink Selection", Box::new(SelectSmallerSyntaxNode))
                            .action(
                                "Add Cursor Above",
                                Box::new(AddSelectionAbove {
                                    skip_soft_wrap: true,
                                }),
                            )
                            .action(
                                "Add Cursor Below",
                                Box::new(AddSelectionBelow {
                                    skip_soft_wrap: true,
                                }),
                            )
                            .when(!disable_ai, |this| {
                                this.separator().action_disabled_when(
                                    !has_selection,
                                    "Add to Agent Thread",
                                    Box::new(AddSelectionToThread),
                                )
                            })
                            .separator()
                            .action("Go to Symbol", Box::new(ToggleOutline))
                            .action("Go to Line/Column", Box::new(ToggleGoToLine))
                            .separator()
                            .action("Next Problem", Box::new(GoToDiagnostic::default()))
                            .action(
                                "Previous Problem",
                                Box::new(GoToPreviousDiagnostic::default()),
                            )
                            .separator()
                            .action_disabled_when(!has_diff_hunks, "Next Hunk", Box::new(GoToHunk))
                            .action_disabled_when(
                                !has_diff_hunks,
                                "Previous Hunk",
                                Box::new(GoToPreviousHunk),
                            )
                            .separator()
                            .action("Move Line Up", Box::new(MoveLineUp))
                            .action("Move Line Down", Box::new(MoveLineDown))
                            .action("Duplicate Selection", Box::new(DuplicateLineDown))
                    });
                    Some(menu)
                })
        });

        let editor_focus_handle = editor.focus_handle(cx);
        let editor = editor.downgrade();
        let editor_settings_dropdown = {
            let vim_mode_enabled = VimModeSetting::get_global(cx).0;
            let helix_mode_enabled = HelixModeSetting::get_global(cx).0;

            PopoverMenu::new("editor-settings")
                .trigger_with_tooltip(
                    IconButton::new("toggle_editor_settings_icon", IconName::Sliders)
                        .icon_size(IconSize::Small)
                        .style(ButtonStyle::Subtle)
                        .toggle_state(self.toggle_settings_handle.is_deployed()),
                    Tooltip::text("Editor Controls"),
                )
                .anchor(Corner::TopRight)
                .with_handle(self.toggle_settings_handle.clone())
                .menu(move |window, cx| {
                    let menu = ContextMenu::build(window, cx, {
                        let focus_handle = editor_focus_handle.clone();
                        |mut menu, _, _| {
                            menu = menu.context(focus_handle);

                            if supports_inlay_hints {
                                menu = menu.toggleable_entry(
                                    "Inlay Hints",
                                    inlay_hints_enabled,
                                    IconPosition::Start,
                                    Some(editor::actions::ToggleInlayHints.boxed_clone()),
                                    {
                                        let editor = editor.clone();
                                        move |window, cx| {
                                            editor
                                                .update(cx, |editor, cx| {
                                                    editor.toggle_inlay_hints(
                                                        &editor::actions::ToggleInlayHints,
                                                        window,
                                                        cx,
                                                    );
                                                })
                                                .ok();
                                        }
                                    },
                                );

                                menu = menu.toggleable_entry(
                                    "Inline Values",
                                    inline_values_enabled,
                                    IconPosition::Start,
                                    Some(editor::actions::ToggleInlineValues.boxed_clone()),
                                    {
                                        let editor = editor.clone();
                                        move |window, cx| {
                                            editor
                                                .update(cx, |editor, cx| {
                                                    editor.toggle_inline_values(
                                                        &editor::actions::ToggleInlineValues,
                                                        window,
                                                        cx,
                                                    );
                                                })
                                                .ok();
                                        }
                                    }
                                );
                            }

                            if supports_minimap {
                                menu = menu.toggleable_entry("Minimap", minimap_enabled, IconPosition::Start, Some(editor::actions::ToggleMinimap.boxed_clone()), {
                                    let editor = editor.clone();
                                    move |window, cx| {
                                        editor
                                            .update(cx, |editor, cx| {
                                                editor.toggle_minimap(
                                                    &editor::actions::ToggleMinimap,
                                                    window,
                                                    cx,
                                                );
                                            })
                                            .ok();
                                    }
                                },)
                            }

                            if has_edit_prediction_provider {
                                let mut edit_prediction_entry = ContextMenuEntry::new("Edit Predictions")
                                    .toggleable(IconPosition::Start, edit_predictions_enabled_at_cursor && show_edit_predictions)
                                    .disabled(!edit_predictions_enabled_at_cursor)
                                    .action(
                                        editor::actions::ToggleEditPrediction.boxed_clone(),
                                    ).handler({
                                        let editor = editor.clone();
                                        move |window, cx| {
                                            editor
                                                .update(cx, |editor, cx| {
                                                    editor.toggle_edit_predictions(
                                                        &editor::actions::ToggleEditPrediction,
                                                        window,
                                                        cx,
                                                    );
                                                })
                                                .ok();
                                        }
                                    });
                                if !edit_predictions_enabled_at_cursor {
                                    edit_prediction_entry = edit_prediction_entry.documentation_aside(DocumentationSide::Left, |_| {
                                        Label::new("You can't toggle edit predictions for this file as it is within the excluded files list.").into_any_element()
                                    });
                                }

                                menu = menu.item(edit_prediction_entry);
                            }

                            menu = menu.separator();

                            if supports_diagnostics {
                                menu = menu.toggleable_entry(
                                    "Diagnostics",
                                    diagnostics_enabled,
                                    IconPosition::Start,
                                    Some(ToggleDiagnostics.boxed_clone()),
                                    {
                                        let editor = editor.clone();
                                        move |window, cx| {
                                            editor
                                                .update(cx, |editor, cx| {
                                                    editor.toggle_diagnostics(
                                                        &ToggleDiagnostics,
                                                        window,
                                                        cx,
                                                    );
                                                })
                                                .ok();
                                        }
                                    },
                                );

                                if supports_inline_diagnostics {
                                    let mut inline_diagnostics_item = ContextMenuEntry::new("Inline Diagnostics")
                                        .toggleable(IconPosition::Start, diagnostics_enabled && inline_diagnostics_enabled)
                                        .action(ToggleInlineDiagnostics.boxed_clone())
                                        .handler({
                                            let editor = editor.clone();
                                            move |window, cx| {
                                                editor
                                                    .update(cx, |editor, cx| {
                                                        editor.toggle_inline_diagnostics(
                                                            &ToggleInlineDiagnostics,
                                                            window,
                                                            cx,
                                                        );
                                                    })
                                                    .ok();
                                            }
                                        });
                                    if !diagnostics_enabled {
                                        inline_diagnostics_item = inline_diagnostics_item.disabled(true).documentation_aside(DocumentationSide::Left, |_|  Label::new("Inline diagnostics are not available until regular diagnostics are enabled.").into_any_element());
                                    }
                                    menu = menu.item(inline_diagnostics_item)
                                }

                                menu = menu.separator();
                            }

                            menu = menu.toggleable_entry(
                                "Line Numbers",
                                show_line_numbers,
                                IconPosition::Start,
                                Some(editor::actions::ToggleLineNumbers.boxed_clone()),
                                {
                                    let editor = editor.clone();
                                    move |window, cx| {
                                        editor
                                            .update(cx, |editor, cx| {
                                                editor.toggle_line_numbers(
                                                    &editor::actions::ToggleLineNumbers,
                                                    window,
                                                    cx,
                                                );
                                            })
                                            .ok();
                                    }
                                },
                            );

                            menu = menu.toggleable_entry(
                                "Selection Menu",
                                selection_menu_enabled,
                                IconPosition::Start,
                                Some(editor::actions::ToggleSelectionMenu.boxed_clone()),
                                {
                                    let editor = editor.clone();
                                    move |window, cx| {
                                        editor
                                            .update(cx, |editor, cx| {
                                                editor.toggle_selection_menu(
                                                    &editor::actions::ToggleSelectionMenu,
                                                    window,
                                                    cx,
                                                )
                                            })
                                            .ok();
                                    }
                                },
                            );

                            menu = menu.toggleable_entry(
                                "Auto Signature Help",
                                auto_signature_help_enabled,
                                IconPosition::Start,
                                Some(editor::actions::ToggleAutoSignatureHelp.boxed_clone()),
                                {
                                    let editor = editor.clone();
                                    move |window, cx| {
                                        editor
                                            .update(cx, |editor, cx| {
                                                editor.toggle_auto_signature_help_menu(
                                                    &editor::actions::ToggleAutoSignatureHelp,
                                                    window,
                                                    cx,
                                                );
                                            })
                                            .ok();
                                    }
                                },
                            );

                            menu = menu.separator();

                            menu = menu.toggleable_entry(
                                "Inline Git Blame",
                                git_blame_inline_enabled,
                                IconPosition::Start,
                                Some(editor::actions::ToggleGitBlameInline.boxed_clone()),
                                {
                                    let editor = editor.clone();
                                    move |window, cx| {
                                        editor
                                            .update(cx, |editor, cx| {
                                                editor.toggle_git_blame_inline(
                                                    &editor::actions::ToggleGitBlameInline,
                                                    window,
                                                    cx,
                                                )
                                            })
                                            .ok();
                                    }
                                },
                            );

                            menu = menu.toggleable_entry(
                                "Column Git Blame",
                                show_git_blame_gutter,
                                IconPosition::Start,
                                Some(git::Blame.boxed_clone()),
                                {
                                    let editor = editor.clone();
                                    move |window, cx| {
                                        editor
                                            .update(cx, |editor, cx| {
                                                editor.toggle_git_blame(
                                                    &git::Blame,
                                                    window,
                                                    cx,
                                                )
                                            })
                                            .ok();
                                    }
                                },
                            );

                            menu = menu.separator();

                            menu = menu.toggleable_entry(
                                "Vim Mode",
                                vim_mode_enabled,
                                IconPosition::Start,
                                None,
                                {
                                    move |window, cx| {
                                        let new_value = !vim_mode_enabled;
                                        VimModeSetting::override_global(VimModeSetting(new_value), cx);
                                        HelixModeSetting::override_global(HelixModeSetting(false), cx);
                                        window.refresh();
                                    }
                                },
                            );
                            menu = menu.toggleable_entry(
                                "Helix Mode",
                                helix_mode_enabled,
                                IconPosition::Start,
                                None,
                                {
                                    move |window, cx| {
                                        let new_value = !helix_mode_enabled;
                                        HelixModeSetting::override_global(HelixModeSetting(new_value), cx);
                                        VimModeSetting::override_global(VimModeSetting(false), cx);
                                        window.refresh();
                                    }
                                }
                            );

                            menu
                        }
                    });
                    Some(menu)
                })
        };

        h_flex()
            .id("quick action bar")
            .gap(DynamicSpacing::Base01.rems(cx))
            .children(secops_button)
            .children(self.render_repl_menu(cx))
            .children(self.render_preview_button(self.workspace.clone(), cx))
            .children(search_button)
            .when(
                AgentSettings::get_global(cx).enabled(cx) && AgentSettings::get_global(cx).button,
                |bar| bar.child(assistant_button),
            )
            .children(code_actions_dropdown)
            .children(editor_selections_dropdown)
            .child(editor_settings_dropdown)
    }
}

impl EventEmitter<ToolbarItemEvent> for QuickActionBar {}

#[derive(IntoElement)]
struct QuickActionBarButton {
    id: ElementId,
    icon: IconName,
    toggled: bool,
    action: Box<dyn Action>,
    focus_handle: FocusHandle,
    tooltip: SharedString,
    on_click: Box<dyn Fn(&ClickEvent, &mut Window, &mut App)>,
}

impl QuickActionBarButton {
    fn new(
        id: impl Into<ElementId>,
        icon: IconName,
        toggled: bool,
        action: Box<dyn Action>,
        focus_handle: FocusHandle,
        tooltip: impl Into<SharedString>,
        on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    ) -> Self {
        Self {
            id: id.into(),
            icon,
            toggled,
            action,
            focus_handle,
            tooltip: tooltip.into(),
            on_click: Box::new(on_click),
        }
    }
}

impl RenderOnce for QuickActionBarButton {
    fn render(self, _window: &mut Window, _: &mut App) -> impl IntoElement {
        let tooltip = self.tooltip.clone();
        let action = self.action.boxed_clone();

        IconButton::new(self.id.clone(), self.icon)
            .icon_size(IconSize::Small)
            .style(ButtonStyle::Subtle)
            .toggle_state(self.toggled)
            .tooltip(move |_window, cx| {
                Tooltip::for_action_in(tooltip.clone(), &*action, &self.focus_handle, cx)
            })
            .on_click(move |event, window, cx| (self.on_click)(event, window, cx))
    }
}

impl ToolbarItemView for QuickActionBar {
    fn set_active_pane_item(
        &mut self,
        active_pane_item: Option<&dyn ItemHandle>,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) -> ToolbarItemLocation {
        self.active_item = active_pane_item.map(ItemHandle::boxed_clone);
        if let Some(active_item) = active_pane_item {
            self._inlay_hints_enabled_subscription.take();

            if let Some(editor) = active_item.downcast::<Editor>() {
                let (mut inlay_hints_enabled, mut supports_inlay_hints) =
                    editor.update(cx, |editor, cx| {
                        (
                            editor.inlay_hints_enabled(),
                            editor.supports_inlay_hints(cx),
                        )
                    });
                self._inlay_hints_enabled_subscription =
                    Some(cx.observe(&editor, move |_, editor, cx| {
                        let (new_inlay_hints_enabled, new_supports_inlay_hints) =
                            editor.update(cx, |editor, cx| {
                                (
                                    editor.inlay_hints_enabled(),
                                    editor.supports_inlay_hints(cx),
                                )
                            });
                        let should_notify = inlay_hints_enabled != new_inlay_hints_enabled
                            || supports_inlay_hints != new_supports_inlay_hints;
                        inlay_hints_enabled = new_inlay_hints_enabled;
                        supports_inlay_hints = new_supports_inlay_hints;
                        if should_notify {
                            cx.notify()
                        }
                    }));
            }
        }
        self.get_toolbar_item_location()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secops_payload_without_truncation() {
        let contents = "safe content";
        let payload = build_secops_payload(contents).expect("payload");
        assert!(!payload.truncated);
        assert!(payload.payload.contains(SECOPS_SYSTEM_PROMPT));
        assert!(payload.payload.contains(contents));
    }

    #[test]
    fn secops_payload_truncates_large_content() {
        let large = "a".repeat(SECOPS_WARN_BYTES + 10);
        let payload = build_secops_payload(&large).expect("payload");
        assert!(payload.truncated);
        assert!(payload.payload.contains("[Content truncated"));
        assert_eq!(payload.original_bytes, large.len());
        assert!(
            payload.payload.len()
                < large.len() + SECOPS_SYSTEM_PROMPT.len() + 256,
            "payload should be bounded after truncation"
        );
    }
}
