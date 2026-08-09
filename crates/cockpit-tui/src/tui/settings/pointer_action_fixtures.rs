//! Typed acceptance inventory for the semantic settings pointer contract.
//!
//! Each fixture enum is deliberately closed. `key_for` exhaustively maps the
//! production vocabulary into this inventory, so adding a production action
//! or a nested source choice fails compilation until its expected outcome is
//! classified here. `all_keys` is derived from the fixture enums themselves;
//! it contains no debug strings, numeric variant counts, or surface tokens.

use super::pointer_actions::*;
use super::providers::{CodexOAuthOption, OAuthOption, OAuthProvider};
use cockpit_core::wizard::ProviderWizardStep;

macro_rules! fixture_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub(super) enum $name { $($variant),+ }
        impl $name {
            const ALL: &'static [Self] = &[$(Self::$variant),+];
        }
    };
}

fixture_enum!(RootFixture { Open });
fixture_enum!(CategoryFixture {
    DescriptorActivate,
    InlineEditBegin,
    InlineEditCommit,
    InlineEditCancel,
    PathEditBegin,
    PathEditCommit,
    PathEditCancel,
    SuggestionSelect,
    TextEditorSave,
    TextEditorCancel,
    PickerSelect,
    ConfirmConfirm,
    ConfirmCancel,
    Reset,
    ExternalEditBeginCursor,
    ExternalEditBeginInline,
    ExternalEditBeginPathEditor,
    ExternalEditBeginTextEditor,
    ExternalEditResultSaved,
    ExternalEditResultCancelled,
    ExternalEditResultFailed
});
fixture_enum!(AgentsFixture {
    Open,
    Edit,
    Delete,
    Reset,
    ResetAll,
    ToggleTool,
    CycleTier,
    Save,
    OpenRawEditor,
    EditText,
    Cancel,
    ExternalEditBegin,
    ExternalEditResultSaved,
    ExternalEditResultCancelled,
    ExternalEditResultFailed
});
fixture_enum!(ToolsFixture {
    CycleWebProvider,
    EditFirecrawlBaseUrl,
    EditCredentialFirecrawl,
    EditCredentialTinyFish,
    EditWebFetchCommand,
    EditWebSearchCommand,
    EditUserToolCommand,
    AddUserTool,
    ToggleUserTool,
    ResetFirecrawlBaseUrl,
    ResetWebFetchCommand,
    ResetWebSearchCommand,
    McpJump,
    Reset,
    DeleteUserTool,
    ReadOnlyBuiltin,
    ReadOnlyMcpTool
});
fixture_enum!(HarnessesFixture {
    Open,
    Add,
    Delete,
    SeedInstalledPresets,
    ResetAndSeedPresets,
    EditCommand,
    EditArgs,
    EditPromptInput,
    EditArgvOverflow,
    EditModelArgs,
    EditDefaultModel,
    EditModels,
    EditModelListArgs,
    EditSupportsJson,
    EditJsonOutputArgs,
    EditSupportsAgentFile,
    EditAgentFileArgs,
    EditAgentFileEnv,
    EditAuthEnvVars,
    EditAuthProbeArgs,
    EditTimeout,
    EditAlwaysAllow,
    Save,
    Cancel
});
fixture_enum!(SkillsFixture {
    ToggleAutoBangCommands,
    ToggleAncestorWalk,
    AddScanDirectory,
    EditScanDirectory,
    DeleteScanDirectory,
    ConfirmDelete,
    CancelDelete,
    Reset
});
fixture_enum!(McpFixture {
    Open,
    Add,
    ToggleEnabled,
    Authenticate,
    Delete,
    EditName,
    ToggleEditorEnabled,
    CycleTransport,
    EditEndpoint,
    EditCommand,
    EditArgs,
    EditBaseEnv,
    CycleAuth,
    EditHeaderName,
    EditHeaderValue,
    EditAuthEnv,
    EditOauthAuthorizeUrl,
    EditOauthTokenUrl,
    EditOauthClientId,
    EditOauthScopes,
    EditCacheTtl,
    EditConnectTimeout,
    EditRequestTimeout,
    Save,
    Cancel
});
fixture_enum!(ProvidersFixture {
    Open,
    Add,
    EditFieldUrl,
    EditHeaders,
    CopilotSetup,
    BeginOAuthGrok,
    BeginOAuthCodex,
    OAuthLogin,
    OAuthManualPaste,
    OAuthPoll,
    OAuthSkipContinue,
    OAuthContinue,
    OAuthAcknowledge,
    ManageModels,
    ProviderSettings,
    Favorite,
    Refetch,
    RefetchAll,
    CycleUnlistedPolicy,
    DeepFetchConfirm,
    BeginDelete,
    DeleteRemoveSecrets,
    DeleteKeepSecrets,
    DeleteCancel,
    SaveProvider,
    LocalBack,
    AddModel,
    RenameModel,
    DeleteModel,
    ModelSettings,
    FetchAllApply,
    FetchAllCancel,
    FetchOneApply,
    FetchOneKeepLocal,
    FetchOneCancel,
    FetchFallbackRetry,
    FetchFallbackKeepLocal,
    FetchFallbackUseFallback,
    FetchFallbackCancel,
    DeepFetchFetch,
    DeepFetchCancel,
    WizardTemplate,
    WizardProviderIdEdit,
    WizardUrlEdit,
    WizardHeadersOpen,
    WizardHeadersAdd,
    WizardHeadersContinue,
    WizardAuthPasteKey,
    WizardAuthEnvVar,
    WizardAuthAdvancedHeaders,
    WizardApiKeyEdit,
    WizardEnvVarEdit,
    WizardTestKey,
    WizardSkipTest,
    WizardGrokLogin,
    WizardGrokManualPaste,
    WizardGrokPoll,
    WizardGrokSkipContinue,
    WizardGrokContinue,
    WizardGrokAcknowledge,
    WizardCodexLogin,
    WizardCodexPoll,
    WizardCodexSkipContinue,
    WizardCodexContinue,
    WizardCodexAcknowledge,
    WizardCopilotNoControl,
    WizardSavingNoControl,
    WizardTestKeyNoControl,
    WizardTestSkippedNoControl,
    WizardFetchingNoControl,
    WizardDoneNoControl,
    RowHeaderOpen,
    RowHeaderAdd,
    RowHeaderSave,
    RowModelOpen,
    RowModelAdd,
    RowModelSave,
    RowSettingEdit,
    RowSettingSave,
    ModelRefresh,
    ModelDiscard,
    ModelRetry,
    ModelReload,
    ModelReapply,
    ModelRebind,
    ModelDismiss,
    CopyAuthorizationUrl,
    CopyDeviceCode,
    CopilotConfirm,
    CopilotCancel
});
fixture_enum!(LspFixture {
    ToggleEnabled,
    CycleAutoInstall,
    ToggleDiagnostics,
    EditOtherFilesLimit,
    EditPerFileLimit,
    EditDebounceMs,
    EditDocumentTimeoutMs,
    EditWorkspaceTimeoutMs,
    SaveOtherFilesLimit,
    SavePerFileLimit,
    SaveDebounceMs,
    SaveDocumentTimeoutMs,
    SaveWorkspaceTimeoutMs,
    CancelOtherFilesLimit,
    CancelPerFileLimit,
    CancelDebounceMs,
    CancelDocumentTimeoutMs,
    CancelWorkspaceTimeoutMs,
    Reset,
    Check,
    Install,
    Uninstall,
    Restart
});
fixture_enum!(ListFixture {
    Add,
    Edit,
    Delete,
    MoveUp,
    MoveDown,
    Save,
    Cancel
});
fixture_enum!(UtilityFixture {
    Select,
    Clear,
    OpenCustom,
    Back,
    EditCustom,
    CommitCustom,
    CancelCustom
});
fixture_enum!(DefaultModelFixture { Choose, Clear });

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ActionFixtureKey {
    Root(RootFixture),
    Category(CategoryFixture),
    Agents(AgentsFixture),
    Tools(ToolsFixture),
    Harnesses(HarnessesFixture),
    Skills(SkillsFixture),
    Mcp(McpFixture),
    Providers(ProvidersFixture),
    Lsp(LspFixture),
    List(ListFixture),
    Utility(UtilityFixture),
    DefaultModel(DefaultModelFixture),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExpectedReducerOutcome {
    Enabled,
    Disabled,
    /// The same semantic action is enabled only when its live row position
    /// permits it (for example move-up/move-down at list boundaries).
    Contextual,
    NoPointerControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum PayloadFixtureKey {
    Root(RootNodeId),
    CategorySetting(super::category::SettingId),
    ProviderSetting(super::settings_editor::ProviderSettingId),
    List(ListKind),
    WizardStep(ProviderWizardStep),
    WizardControl(WizardPayloadControlKey),
    OAuthProvider(OAuthProvider),
    OAuthOption(OAuthOption),
}

impl PayloadFixtureKey {
    pub(super) fn expects_pointer_control(self) -> bool {
        !matches!(
            self,
            Self::WizardStep(
                ProviderWizardStep::CopilotAuth
                    | ProviderWizardStep::Saving
                    | ProviderWizardStep::TestKey
                    | ProviderWizardStep::TestSkipped
                    | ProviderWizardStep::Fetching
                    | ProviderWizardStep::Done
            )
        )
    }
}

fixture_enum!(WizardPayloadControlKey {
    Template,
    AuthPasteKey,
    AuthEnvVar,
    AuthAdvancedHeaders,
    TestKey,
    SkipTest,
    OAuthLogin,
    OAuthManualPaste,
    OAuthPoll,
    OAuthSkipContinue,
    OAuthContinue,
    OAuthAcknowledge,
    Header,
    AddHeader,
    ContinueHeaders,
    EditText
});

fn wizard_payload_key(control: &WizardControlId) -> WizardPayloadControlKey {
    match control {
        WizardControlId::Template(_) => WizardPayloadControlKey::Template,
        WizardControlId::AuthMethod(WizardAuthMethod::PasteKey) => {
            WizardPayloadControlKey::AuthPasteKey
        }
        WizardControlId::AuthMethod(WizardAuthMethod::EnvVar) => {
            WizardPayloadControlKey::AuthEnvVar
        }
        WizardControlId::AuthMethod(WizardAuthMethod::AdvancedHeaders) => {
            WizardPayloadControlKey::AuthAdvancedHeaders
        }
        WizardControlId::TestChoice(WizardTestChoice::TestKey) => WizardPayloadControlKey::TestKey,
        WizardControlId::TestChoice(WizardTestChoice::SkipTest) => {
            WizardPayloadControlKey::SkipTest
        }
        WizardControlId::OAuth(OAuthOption::Login) => WizardPayloadControlKey::OAuthLogin,
        WizardControlId::OAuth(OAuthOption::ManualPaste) => {
            WizardPayloadControlKey::OAuthManualPaste
        }
        WizardControlId::OAuth(OAuthOption::Poll) => WizardPayloadControlKey::OAuthPoll,
        WizardControlId::OAuth(OAuthOption::SkipContinue) => {
            WizardPayloadControlKey::OAuthSkipContinue
        }
        WizardControlId::OAuth(OAuthOption::Continue) => WizardPayloadControlKey::OAuthContinue,
        WizardControlId::OAuth(OAuthOption::Acknowledge) => {
            WizardPayloadControlKey::OAuthAcknowledge
        }
        WizardControlId::Header(_) => WizardPayloadControlKey::Header,
        WizardControlId::AddHeader => WizardPayloadControlKey::AddHeader,
        WizardControlId::ContinueHeaders => WizardPayloadControlKey::ContinueHeaders,
        WizardControlId::EditText => WizardPayloadControlKey::EditText,
    }
}

pub(super) fn all_payload_keys() -> Vec<PayloadFixtureKey> {
    let mut all = Vec::new();
    all.extend(RootNodeId::ALL.into_iter().map(PayloadFixtureKey::Root));
    all.extend(
        super::category::ALL_SETTING_IDS
            .iter()
            .copied()
            .map(PayloadFixtureKey::CategorySetting),
    );
    all.extend(
        super::settings_editor::ALL_PROVIDER_SETTING_IDS
            .iter()
            .copied()
            .map(PayloadFixtureKey::ProviderSetting),
    );
    all.extend([
        PayloadFixtureKey::List(ListKind::Instructions),
        PayloadFixtureKey::List(ListKind::RedactPatterns),
        PayloadFixtureKey::List(ListKind::String(
            super::string_list::StringListKind::AgentDirs,
        )),
        PayloadFixtureKey::List(ListKind::String(
            super::string_list::StringListKind::ExtraDotenvPaths,
        )),
        PayloadFixtureKey::List(ListKind::String(
            super::string_list::StringListKind::RedactDenylist,
        )),
        PayloadFixtureKey::List(ListKind::String(
            super::string_list::StringListKind::RedactAllowlist,
        )),
        PayloadFixtureKey::List(ListKind::String(
            super::string_list::StringListKind::GitignoreAllow,
        )),
    ]);
    all.extend(
        ProviderWizardStep::ALL
            .into_iter()
            .map(PayloadFixtureKey::WizardStep),
    );
    all.extend(
        WizardPayloadControlKey::ALL
            .iter()
            .copied()
            .map(PayloadFixtureKey::WizardControl),
    );
    all.extend([OAuthProvider::Grok, OAuthProvider::Codex].map(PayloadFixtureKey::OAuthProvider));
    all.extend(
        [
            OAuthOption::Login,
            OAuthOption::ManualPaste,
            OAuthOption::Poll,
            OAuthOption::SkipContinue,
            OAuthOption::Continue,
            OAuthOption::Acknowledge,
        ]
        .map(PayloadFixtureKey::OAuthOption),
    );
    all
}

pub(super) fn payload_keys_for(action: &SettingsPointerAction) -> Vec<PayloadFixtureKey> {
    match action {
        SettingsPointerAction::Root(RootAction::Open(id)) => vec![PayloadFixtureKey::Root(*id)],
        SettingsPointerAction::Category(action) => match action {
            CategoryAction::DescriptorActivate(id)
            | CategoryAction::InlineEditBegin(id)
            | CategoryAction::InlineEditCommit(id)
            | CategoryAction::InlineEditCancel(id)
            | CategoryAction::PathEditBegin(id)
            | CategoryAction::PathEditCommit(id)
            | CategoryAction::PathEditCancel(id)
            | CategoryAction::TextEditorSave(id)
            | CategoryAction::TextEditorCancel(id)
            | CategoryAction::Confirm(id, _)
            | CategoryAction::ExternalEditBegin(id, _)
            | CategoryAction::ExternalEditResult(id, _) => {
                vec![PayloadFixtureKey::CategorySetting(*id)]
            }
            CategoryAction::SuggestionSelect(id, _) | CategoryAction::PickerSelect(id, _) => {
                vec![PayloadFixtureKey::CategorySetting(*id)]
            }
            CategoryAction::Reset => Vec::new(),
        },
        SettingsPointerAction::Providers(ProvidersAction::WizardControl(step, control)) => vec![
            PayloadFixtureKey::WizardStep(*step),
            PayloadFixtureKey::WizardControl(wizard_payload_key(control)),
        ],
        SettingsPointerAction::Providers(ProvidersAction::BeginOAuth(_, provider)) => {
            vec![PayloadFixtureKey::OAuthProvider(*provider)]
        }
        SettingsPointerAction::Providers(ProvidersAction::OAuthOption(_, option)) => {
            vec![PayloadFixtureKey::OAuthOption(*option)]
        }
        SettingsPointerAction::Providers(ProvidersAction::RowEditor(
            ProviderRowEditorAction::SettingEdit(id),
        )) => vec![PayloadFixtureKey::ProviderSetting(*id)],
        SettingsPointerAction::List(action) => match action {
            ListAction::Edit(id)
            | ListAction::Delete(id)
            | ListAction::MoveUp(id)
            | ListAction::MoveDown(id) => vec![PayloadFixtureKey::List(id.kind)],
            ListAction::Add | ListAction::Save | ListAction::Cancel => Vec::new(),
        },
        SettingsPointerAction::Agents(_)
        | SettingsPointerAction::Tools(_)
        | SettingsPointerAction::Harnesses(_)
        | SettingsPointerAction::Skills(_)
        | SettingsPointerAction::Mcp(_)
        | SettingsPointerAction::Providers(_)
        | SettingsPointerAction::Lsp(_)
        | SettingsPointerAction::UtilityModel(_)
        | SettingsPointerAction::DefaultModel(_) => Vec::new(),
    }
}

impl ActionFixtureKey {
    pub(super) fn expected(self) -> ExpectedReducerOutcome {
        match self {
            Self::Tools(ToolsFixture::ReadOnlyBuiltin | ToolsFixture::ReadOnlyMcpTool) => {
                ExpectedReducerOutcome::Disabled
            }
            Self::Providers(
                ProvidersFixture::WizardCopilotNoControl
                | ProvidersFixture::WizardSavingNoControl
                | ProvidersFixture::WizardTestKeyNoControl
                | ProvidersFixture::WizardTestSkippedNoControl
                | ProvidersFixture::WizardFetchingNoControl
                | ProvidersFixture::WizardDoneNoControl,
            ) => ExpectedReducerOutcome::NoPointerControl,
            Self::List(ListFixture::MoveUp | ListFixture::MoveDown) => {
                ExpectedReducerOutcome::Contextual
            }
            Self::Root(_)
            | Self::Category(_)
            | Self::Agents(_)
            | Self::Tools(_)
            | Self::Harnesses(_)
            | Self::Skills(_)
            | Self::Mcp(_)
            | Self::Providers(_)
            | Self::Lsp(_)
            | Self::List(_)
            | Self::Utility(_)
            | Self::DefaultModel(_) => ExpectedReducerOutcome::Enabled,
        }
    }
}

pub(super) fn all_keys() -> Vec<ActionFixtureKey> {
    let mut all = Vec::new();
    all.extend(RootFixture::ALL.iter().copied().map(ActionFixtureKey::Root));
    all.extend(
        CategoryFixture::ALL
            .iter()
            .copied()
            .map(ActionFixtureKey::Category),
    );
    all.extend(
        AgentsFixture::ALL
            .iter()
            .copied()
            .map(ActionFixtureKey::Agents),
    );
    all.extend(
        ToolsFixture::ALL
            .iter()
            .copied()
            .map(ActionFixtureKey::Tools),
    );
    all.extend(
        HarnessesFixture::ALL
            .iter()
            .copied()
            .map(ActionFixtureKey::Harnesses),
    );
    all.extend(
        SkillsFixture::ALL
            .iter()
            .copied()
            .map(ActionFixtureKey::Skills),
    );
    all.extend(McpFixture::ALL.iter().copied().map(ActionFixtureKey::Mcp));
    all.extend(
        ProvidersFixture::ALL
            .iter()
            .copied()
            .map(ActionFixtureKey::Providers),
    );
    all.extend(LspFixture::ALL.iter().copied().map(ActionFixtureKey::Lsp));
    all.extend(ListFixture::ALL.iter().copied().map(ActionFixtureKey::List));
    all.extend(
        UtilityFixture::ALL
            .iter()
            .copied()
            .map(ActionFixtureKey::Utility),
    );
    all.extend(
        DefaultModelFixture::ALL
            .iter()
            .copied()
            .map(ActionFixtureKey::DefaultModel),
    );
    all
}

fn grok_oauth_fixture(option: OAuthOption) -> ProvidersFixture {
    match option {
        OAuthOption::Login => ProvidersFixture::WizardGrokLogin,
        OAuthOption::ManualPaste => ProvidersFixture::WizardGrokManualPaste,
        OAuthOption::Poll => ProvidersFixture::WizardGrokPoll,
        OAuthOption::SkipContinue => ProvidersFixture::WizardGrokSkipContinue,
        OAuthOption::Continue => ProvidersFixture::WizardGrokContinue,
        OAuthOption::Acknowledge => ProvidersFixture::WizardGrokAcknowledge,
    }
}

fn codex_oauth_fixture(option: OAuthOption) -> ProvidersFixture {
    let option = CodexOAuthOption::try_from(option)
        .expect("Codex wizard controls come from the sealed device-authorization inventory");
    match option {
        CodexOAuthOption::Login => ProvidersFixture::WizardCodexLogin,
        CodexOAuthOption::Poll => ProvidersFixture::WizardCodexPoll,
        CodexOAuthOption::SkipContinue => ProvidersFixture::WizardCodexSkipContinue,
        CodexOAuthOption::Continue => ProvidersFixture::WizardCodexContinue,
        CodexOAuthOption::Acknowledge => ProvidersFixture::WizardCodexAcknowledge,
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn key_for(action: &SettingsPointerAction) -> ActionFixtureKey {
    use ActionFixtureKey as K;
    match action {
        SettingsPointerAction::Root(RootAction::Open(_)) => K::Root(RootFixture::Open),
        SettingsPointerAction::Category(action) => K::Category(match action {
            CategoryAction::DescriptorActivate(_) => CategoryFixture::DescriptorActivate,
            CategoryAction::InlineEditBegin(_) => CategoryFixture::InlineEditBegin,
            CategoryAction::InlineEditCommit(_) => CategoryFixture::InlineEditCommit,
            CategoryAction::InlineEditCancel(_) => CategoryFixture::InlineEditCancel,
            CategoryAction::PathEditBegin(_) => CategoryFixture::PathEditBegin,
            CategoryAction::PathEditCommit(_) => CategoryFixture::PathEditCommit,
            CategoryAction::PathEditCancel(_) => CategoryFixture::PathEditCancel,
            CategoryAction::SuggestionSelect(_, _) => CategoryFixture::SuggestionSelect,
            CategoryAction::TextEditorSave(_) => CategoryFixture::TextEditorSave,
            CategoryAction::TextEditorCancel(_) => CategoryFixture::TextEditorCancel,
            CategoryAction::PickerSelect(_, _) => CategoryFixture::PickerSelect,
            CategoryAction::Confirm(_, ConfirmationChoice::Confirm) => {
                CategoryFixture::ConfirmConfirm
            }
            CategoryAction::Confirm(_, ConfirmationChoice::Cancel) => {
                CategoryFixture::ConfirmCancel
            }
            CategoryAction::Reset => CategoryFixture::Reset,
            CategoryAction::ExternalEditBegin(_, source) => match source {
                CategoryExternalSource::Cursor => CategoryFixture::ExternalEditBeginCursor,
                CategoryExternalSource::Inline => CategoryFixture::ExternalEditBeginInline,
                CategoryExternalSource::PathEditor => CategoryFixture::ExternalEditBeginPathEditor,
                CategoryExternalSource::TextEditor => CategoryFixture::ExternalEditBeginTextEditor,
            },
            CategoryAction::ExternalEditResult(_, result) => match result {
                ExternalEditOutcome::Saved => CategoryFixture::ExternalEditResultSaved,
                ExternalEditOutcome::Cancelled => CategoryFixture::ExternalEditResultCancelled,
                ExternalEditOutcome::Failed => CategoryFixture::ExternalEditResultFailed,
            },
        }),
        SettingsPointerAction::Agents(action) => K::Agents(match action {
            AgentsAction::Open(_) => AgentsFixture::Open,
            AgentsAction::Edit(_) => AgentsFixture::Edit,
            AgentsAction::Delete(_) => AgentsFixture::Delete,
            AgentsAction::Reset(_) => AgentsFixture::Reset,
            AgentsAction::ResetAll => AgentsFixture::ResetAll,
            AgentsAction::ToggleTool(_, _) => AgentsFixture::ToggleTool,
            AgentsAction::CycleTier(_, _) => AgentsFixture::CycleTier,
            AgentsAction::Save(_) => AgentsFixture::Save,
            AgentsAction::OpenRawEditor(_) => AgentsFixture::OpenRawEditor,
            AgentsAction::EditText(_) => AgentsFixture::EditText,
            AgentsAction::Cancel(_) => AgentsFixture::Cancel,
            AgentsAction::ExternalEditBegin(_) => AgentsFixture::ExternalEditBegin,
            AgentsAction::ExternalEditResult(_, ExternalEditOutcome::Saved) => {
                AgentsFixture::ExternalEditResultSaved
            }
            AgentsAction::ExternalEditResult(_, ExternalEditOutcome::Cancelled) => {
                AgentsFixture::ExternalEditResultCancelled
            }
            AgentsAction::ExternalEditResult(_, ExternalEditOutcome::Failed) => {
                AgentsFixture::ExternalEditResultFailed
            }
        }),
        SettingsPointerAction::Tools(action) => K::Tools(match action {
            ToolsAction::CycleWebProvider => ToolsFixture::CycleWebProvider,
            ToolsAction::EditFirecrawlBaseUrl => ToolsFixture::EditFirecrawlBaseUrl,
            ToolsAction::EditCredential(CredentialKind::Firecrawl) => {
                ToolsFixture::EditCredentialFirecrawl
            }
            ToolsAction::EditCredential(CredentialKind::TinyFish) => {
                ToolsFixture::EditCredentialTinyFish
            }
            ToolsAction::EditWebFetchCommand => ToolsFixture::EditWebFetchCommand,
            ToolsAction::EditWebSearchCommand => ToolsFixture::EditWebSearchCommand,
            ToolsAction::EditUserToolCommand(_) => ToolsFixture::EditUserToolCommand,
            ToolsAction::AddUserTool => ToolsFixture::AddUserTool,
            ToolsAction::ToggleUserTool(_) => ToolsFixture::ToggleUserTool,
            ToolsAction::ResetToolField(ToolFieldId::FirecrawlBaseUrl) => {
                ToolsFixture::ResetFirecrawlBaseUrl
            }
            ToolsAction::ResetToolField(ToolFieldId::WebFetchCommand) => {
                ToolsFixture::ResetWebFetchCommand
            }
            ToolsAction::ResetToolField(ToolFieldId::WebSearchCommand) => {
                ToolsFixture::ResetWebSearchCommand
            }
            ToolsAction::McpJump => ToolsFixture::McpJump,
            ToolsAction::Reset => ToolsFixture::Reset,
            ToolsAction::DeleteUserTool(_) => ToolsFixture::DeleteUserTool,
            ToolsAction::ReadOnlyBuiltin(_) => ToolsFixture::ReadOnlyBuiltin,
            ToolsAction::ReadOnlyMcpTool(_, _) => ToolsFixture::ReadOnlyMcpTool,
        }),
        SettingsPointerAction::Harnesses(action) => K::Harnesses(match action {
            HarnessesAction::Open(_) => HarnessesFixture::Open,
            HarnessesAction::Add => HarnessesFixture::Add,
            HarnessesAction::Delete(_) => HarnessesFixture::Delete,
            HarnessesAction::SeedInstalledPresets => HarnessesFixture::SeedInstalledPresets,
            HarnessesAction::ResetAndSeedPresets => HarnessesFixture::ResetAndSeedPresets,
            HarnessesAction::EditField(field) => match field {
                HarnessField::Command => HarnessesFixture::EditCommand,
                HarnessField::Args => HarnessesFixture::EditArgs,
                HarnessField::PromptInput => HarnessesFixture::EditPromptInput,
                HarnessField::ArgvOverflow => HarnessesFixture::EditArgvOverflow,
                HarnessField::ModelArgs => HarnessesFixture::EditModelArgs,
                HarnessField::DefaultModel => HarnessesFixture::EditDefaultModel,
                HarnessField::Models => HarnessesFixture::EditModels,
                HarnessField::ModelListArgs => HarnessesFixture::EditModelListArgs,
                HarnessField::SupportsJson => HarnessesFixture::EditSupportsJson,
                HarnessField::JsonOutputArgs => HarnessesFixture::EditJsonOutputArgs,
                HarnessField::SupportsAgentFile => HarnessesFixture::EditSupportsAgentFile,
                HarnessField::AgentFileArgs => HarnessesFixture::EditAgentFileArgs,
                HarnessField::AgentFileEnv => HarnessesFixture::EditAgentFileEnv,
                HarnessField::AuthEnvVars => HarnessesFixture::EditAuthEnvVars,
                HarnessField::AuthProbeArgs => HarnessesFixture::EditAuthProbeArgs,
                HarnessField::Timeout => HarnessesFixture::EditTimeout,
                HarnessField::AlwaysAllow => HarnessesFixture::EditAlwaysAllow,
            },
            HarnessesAction::Save => HarnessesFixture::Save,
            HarnessesAction::Cancel => HarnessesFixture::Cancel,
        }),
        SettingsPointerAction::Skills(action) => K::Skills(match action {
            SkillsAction::ToggleAutoBangCommands => SkillsFixture::ToggleAutoBangCommands,
            SkillsAction::ToggleAncestorWalk => SkillsFixture::ToggleAncestorWalk,
            SkillsAction::AddScanDirectory => SkillsFixture::AddScanDirectory,
            SkillsAction::EditScanDirectory(_) => SkillsFixture::EditScanDirectory,
            SkillsAction::DeleteScanDirectory(_) => SkillsFixture::DeleteScanDirectory,
            SkillsAction::ConfirmDeleteScanDirectory(_, ConfirmationChoice::Confirm) => {
                SkillsFixture::ConfirmDelete
            }
            SkillsAction::ConfirmDeleteScanDirectory(_, ConfirmationChoice::Cancel) => {
                SkillsFixture::CancelDelete
            }
            SkillsAction::Reset => SkillsFixture::Reset,
        }),
        SettingsPointerAction::Mcp(action) => K::Mcp(match action {
            McpAction::Open(_) => McpFixture::Open,
            McpAction::Add => McpFixture::Add,
            McpAction::ToggleEnabled(_) => McpFixture::ToggleEnabled,
            McpAction::Authenticate(_) => McpFixture::Authenticate,
            McpAction::Delete(_) => McpFixture::Delete,
            McpAction::EditName => McpFixture::EditName,
            McpAction::ToggleEditorEnabled => McpFixture::ToggleEditorEnabled,
            McpAction::CycleTransport => McpFixture::CycleTransport,
            McpAction::EditEndpoint => McpFixture::EditEndpoint,
            McpAction::EditCommand => McpFixture::EditCommand,
            McpAction::EditArgs => McpFixture::EditArgs,
            McpAction::EditBaseEnv => McpFixture::EditBaseEnv,
            McpAction::CycleAuth => McpFixture::CycleAuth,
            McpAction::EditHeaderName => McpFixture::EditHeaderName,
            McpAction::EditHeaderValue => McpFixture::EditHeaderValue,
            McpAction::EditAuthEnv => McpFixture::EditAuthEnv,
            McpAction::EditOauthAuthorizeUrl => McpFixture::EditOauthAuthorizeUrl,
            McpAction::EditOauthTokenUrl => McpFixture::EditOauthTokenUrl,
            McpAction::EditOauthClientId => McpFixture::EditOauthClientId,
            McpAction::EditOauthScopes => McpFixture::EditOauthScopes,
            McpAction::EditCacheTtl => McpFixture::EditCacheTtl,
            McpAction::EditConnectTimeout => McpFixture::EditConnectTimeout,
            McpAction::EditRequestTimeout => McpFixture::EditRequestTimeout,
            McpAction::Save => McpFixture::Save,
            McpAction::Cancel => McpFixture::Cancel,
        }),
        SettingsPointerAction::Providers(action) => K::Providers(provider_key(action)),
        SettingsPointerAction::Lsp(action) => K::Lsp(lsp_key(action)),
        SettingsPointerAction::List(action) => K::List(match action {
            ListAction::Add => ListFixture::Add,
            ListAction::Edit(_) => ListFixture::Edit,
            ListAction::Delete(_) => ListFixture::Delete,
            ListAction::MoveUp(_) => ListFixture::MoveUp,
            ListAction::MoveDown(_) => ListFixture::MoveDown,
            ListAction::Save => ListFixture::Save,
            ListAction::Cancel => ListFixture::Cancel,
        }),
        SettingsPointerAction::UtilityModel(action) => K::Utility(match action {
            UtilityModelAction::Select(_) => UtilityFixture::Select,
            UtilityModelAction::Clear => UtilityFixture::Clear,
            UtilityModelAction::OpenCustom => UtilityFixture::OpenCustom,
            UtilityModelAction::Back => UtilityFixture::Back,
            UtilityModelAction::EditCustom => UtilityFixture::EditCustom,
            UtilityModelAction::CommitCustom => UtilityFixture::CommitCustom,
            UtilityModelAction::CancelCustom => UtilityFixture::CancelCustom,
        }),
        SettingsPointerAction::DefaultModel(DefaultModelAction::Choose) => {
            K::DefaultModel(DefaultModelFixture::Choose)
        }
        SettingsPointerAction::DefaultModel(DefaultModelAction::Clear) => {
            K::DefaultModel(DefaultModelFixture::Clear)
        }
    }
}

fn row_key(action: &ProviderRowEditorAction) -> ProvidersFixture {
    match action {
        ProviderRowEditorAction::HeaderOpen(_) => ProvidersFixture::RowHeaderOpen,
        ProviderRowEditorAction::HeaderAdd => ProvidersFixture::RowHeaderAdd,
        ProviderRowEditorAction::HeaderSave => ProvidersFixture::RowHeaderSave,
        ProviderRowEditorAction::ModelOpen(_) => ProvidersFixture::RowModelOpen,
        ProviderRowEditorAction::ModelAdd => ProvidersFixture::RowModelAdd,
        ProviderRowEditorAction::ModelSave => ProvidersFixture::RowModelSave,
        ProviderRowEditorAction::SettingEdit(_) => ProvidersFixture::RowSettingEdit,
        ProviderRowEditorAction::SettingSave => ProvidersFixture::RowSettingSave,
    }
}

#[derive(Clone, Copy)]
enum WizardControlKind {
    Template,
    AuthPasteKey,
    AuthEnvVar,
    AuthAdvancedHeaders,
    TestKey,
    SkipTest,
    OAuth(OAuthOption),
    Header,
    AddHeader,
    ContinueHeaders,
    EditText,
}

fn wizard_control_kind(control: &WizardControlId) -> WizardControlKind {
    match control {
        WizardControlId::Template(_) => WizardControlKind::Template,
        WizardControlId::AuthMethod(WizardAuthMethod::PasteKey) => WizardControlKind::AuthPasteKey,
        WizardControlId::AuthMethod(WizardAuthMethod::EnvVar) => WizardControlKind::AuthEnvVar,
        WizardControlId::AuthMethod(WizardAuthMethod::AdvancedHeaders) => {
            WizardControlKind::AuthAdvancedHeaders
        }
        WizardControlId::TestChoice(WizardTestChoice::TestKey) => WizardControlKind::TestKey,
        WizardControlId::TestChoice(WizardTestChoice::SkipTest) => WizardControlKind::SkipTest,
        WizardControlId::OAuth(option) => WizardControlKind::OAuth(*option),
        WizardControlId::Header(_) => WizardControlKind::Header,
        WizardControlId::AddHeader => WizardControlKind::AddHeader,
        WizardControlId::ContinueHeaders => WizardControlKind::ContinueHeaders,
        WizardControlId::EditText => WizardControlKind::EditText,
    }
}

fn wizard_key(step: ProviderWizardStep, control: &WizardControlId) -> ProvidersFixture {
    let control = wizard_control_kind(control);
    match step {
        ProviderWizardStep::Template if matches!(control, WizardControlKind::Template) => {
            ProvidersFixture::WizardTemplate
        }
        ProviderWizardStep::ProviderId if matches!(control, WizardControlKind::EditText) => {
            ProvidersFixture::WizardProviderIdEdit
        }
        ProviderWizardStep::Url if matches!(control, WizardControlKind::EditText) => {
            ProvidersFixture::WizardUrlEdit
        }
        ProviderWizardStep::Headers if matches!(control, WizardControlKind::Header) => {
            ProvidersFixture::WizardHeadersOpen
        }
        ProviderWizardStep::Headers if matches!(control, WizardControlKind::AddHeader) => {
            ProvidersFixture::WizardHeadersAdd
        }
        ProviderWizardStep::Headers if matches!(control, WizardControlKind::ContinueHeaders) => {
            ProvidersFixture::WizardHeadersContinue
        }
        ProviderWizardStep::AuthMethod if matches!(control, WizardControlKind::AuthPasteKey) => {
            ProvidersFixture::WizardAuthPasteKey
        }
        ProviderWizardStep::AuthMethod if matches!(control, WizardControlKind::AuthEnvVar) => {
            ProvidersFixture::WizardAuthEnvVar
        }
        ProviderWizardStep::AuthMethod
            if matches!(control, WizardControlKind::AuthAdvancedHeaders) =>
        {
            ProvidersFixture::WizardAuthAdvancedHeaders
        }
        ProviderWizardStep::ApiKey if matches!(control, WizardControlKind::EditText) => {
            ProvidersFixture::WizardApiKeyEdit
        }
        ProviderWizardStep::EnvVar if matches!(control, WizardControlKind::EditText) => {
            ProvidersFixture::WizardEnvVarEdit
        }
        ProviderWizardStep::TestKeyChoice if matches!(control, WizardControlKind::TestKey) => {
            ProvidersFixture::WizardTestKey
        }
        ProviderWizardStep::TestKeyChoice if matches!(control, WizardControlKind::SkipTest) => {
            ProvidersFixture::WizardSkipTest
        }
        ProviderWizardStep::GrokOAuth => {
            let WizardControlKind::OAuth(option) = control else {
                unreachable!("wizard control does not belong to Grok OAuth")
            };
            grok_oauth_fixture(option)
        }
        ProviderWizardStep::CodexOAuth => {
            let WizardControlKind::OAuth(option) = control else {
                unreachable!("wizard control does not belong to Codex OAuth")
            };
            codex_oauth_fixture(option)
        }
        ProviderWizardStep::CopilotAuth
        | ProviderWizardStep::Saving
        | ProviderWizardStep::TestKey
        | ProviderWizardStep::TestSkipped
        | ProviderWizardStep::Fetching
        | ProviderWizardStep::Done => {
            unreachable!("non-interactive provider wizard step cannot publish a pointer control")
        }
        ProviderWizardStep::Template
        | ProviderWizardStep::ProviderId
        | ProviderWizardStep::Url
        | ProviderWizardStep::Headers
        | ProviderWizardStep::AuthMethod
        | ProviderWizardStep::ApiKey
        | ProviderWizardStep::EnvVar
        | ProviderWizardStep::TestKeyChoice => {
            unreachable!("wizard control does not belong to its sealed source step")
        }
    }
}

#[allow(clippy::too_many_lines)]
fn provider_key(action: &ProvidersAction) -> ProvidersFixture {
    match action {
        ProvidersAction::Open(_) => ProvidersFixture::Open,
        ProvidersAction::Add => ProvidersFixture::Add,
        ProvidersAction::EditField(_, super::providers::EditField::Url) => {
            ProvidersFixture::EditFieldUrl
        }
        ProvidersAction::EditHeaders(_) => ProvidersFixture::EditHeaders,
        ProvidersAction::CopilotSetup(_) => ProvidersFixture::CopilotSetup,
        ProvidersAction::BeginOAuth(_, OAuthProvider::Grok) => ProvidersFixture::BeginOAuthGrok,
        ProvidersAction::BeginOAuth(_, OAuthProvider::Codex) => ProvidersFixture::BeginOAuthCodex,
        ProvidersAction::OAuthOption(_, OAuthOption::Login) => ProvidersFixture::OAuthLogin,
        ProvidersAction::OAuthOption(_, OAuthOption::ManualPaste) => {
            ProvidersFixture::OAuthManualPaste
        }
        ProvidersAction::OAuthOption(_, OAuthOption::Poll) => ProvidersFixture::OAuthPoll,
        ProvidersAction::OAuthOption(_, OAuthOption::SkipContinue) => {
            ProvidersFixture::OAuthSkipContinue
        }
        ProvidersAction::OAuthOption(_, OAuthOption::Continue) => ProvidersFixture::OAuthContinue,
        ProvidersAction::OAuthOption(_, OAuthOption::Acknowledge) => {
            ProvidersFixture::OAuthAcknowledge
        }
        ProvidersAction::ManageModels(_) => ProvidersFixture::ManageModels,
        ProvidersAction::ProviderSettings(_) => ProvidersFixture::ProviderSettings,
        ProvidersAction::Favorite(_) => ProvidersFixture::Favorite,
        ProvidersAction::Refetch(_) => ProvidersFixture::Refetch,
        ProvidersAction::RefetchAll => ProvidersFixture::RefetchAll,
        ProvidersAction::CycleUnlistedPolicy => ProvidersFixture::CycleUnlistedPolicy,
        ProvidersAction::DeepFetchConfirm(_) => ProvidersFixture::DeepFetchConfirm,
        ProvidersAction::BeginDelete(_) => ProvidersFixture::BeginDelete,
        ProvidersAction::Delete(_, ProviderDeleteChoice::RemoveSecrets) => {
            ProvidersFixture::DeleteRemoveSecrets
        }
        ProvidersAction::Delete(_, ProviderDeleteChoice::KeepSecrets) => {
            ProvidersFixture::DeleteKeepSecrets
        }
        ProvidersAction::Delete(_, ProviderDeleteChoice::Cancel) => ProvidersFixture::DeleteCancel,
        ProvidersAction::SaveProvider(_) => ProvidersFixture::SaveProvider,
        ProvidersAction::LocalBack => ProvidersFixture::LocalBack,
        ProvidersAction::AddModel(_) => ProvidersFixture::AddModel,
        ProvidersAction::RenameModel(_, _) => ProvidersFixture::RenameModel,
        ProvidersAction::DeleteModel(_, _) => ProvidersFixture::DeleteModel,
        ProvidersAction::ModelSettings(_, _) => ProvidersFixture::ModelSettings,
        ProvidersAction::FetchAllConfirm(FetchAllChoice::Apply) => ProvidersFixture::FetchAllApply,
        ProvidersAction::FetchAllConfirm(FetchAllChoice::Cancel) => {
            ProvidersFixture::FetchAllCancel
        }
        ProvidersAction::FetchOneConfirm(_, FetchOneChoice::Apply) => {
            ProvidersFixture::FetchOneApply
        }
        ProvidersAction::FetchOneConfirm(_, FetchOneChoice::KeepLocal) => {
            ProvidersFixture::FetchOneKeepLocal
        }
        ProvidersAction::FetchOneConfirm(_, FetchOneChoice::Cancel) => {
            ProvidersFixture::FetchOneCancel
        }
        ProvidersAction::FetchFallbackConfirm(_, FetchFallbackChoice::Retry) => {
            ProvidersFixture::FetchFallbackRetry
        }
        ProvidersAction::FetchFallbackConfirm(_, FetchFallbackChoice::KeepLocal) => {
            ProvidersFixture::FetchFallbackKeepLocal
        }
        ProvidersAction::FetchFallbackConfirm(_, FetchFallbackChoice::UseFallback) => {
            ProvidersFixture::FetchFallbackUseFallback
        }
        ProvidersAction::FetchFallbackConfirm(_, FetchFallbackChoice::Cancel) => {
            ProvidersFixture::FetchFallbackCancel
        }
        ProvidersAction::DeepFetchChoice(_, DeepFetchChoice::Fetch) => {
            ProvidersFixture::DeepFetchFetch
        }
        ProvidersAction::DeepFetchChoice(_, DeepFetchChoice::Cancel) => {
            ProvidersFixture::DeepFetchCancel
        }
        ProvidersAction::WizardControl(step, control) => wizard_key(*step, control),
        ProvidersAction::RowEditor(action) => row_key(action),
        ProvidersAction::ModelLifecycle(ModelLifecycleAction::Refresh(_, _)) => {
            ProvidersFixture::ModelRefresh
        }
        ProvidersAction::ModelLifecycle(ModelLifecycleAction::Discard(_, _)) => {
            ProvidersFixture::ModelDiscard
        }
        ProvidersAction::ModelLifecycle(ModelLifecycleAction::Retry(_, _)) => {
            ProvidersFixture::ModelRetry
        }
        ProvidersAction::ModelLifecycle(ModelLifecycleAction::Reload(_, _)) => {
            ProvidersFixture::ModelReload
        }
        ProvidersAction::ModelLifecycle(ModelLifecycleAction::Reapply) => {
            ProvidersFixture::ModelReapply
        }
        ProvidersAction::ModelLifecycle(ModelLifecycleAction::Rebind) => {
            ProvidersFixture::ModelRebind
        }
        ProvidersAction::ModelLifecycle(ModelLifecycleAction::Dismiss) => {
            ProvidersFixture::ModelDismiss
        }
        ProvidersAction::CopyOAuth(_, OAuthCopyKind::AuthorizationUrl) => {
            ProvidersFixture::CopyAuthorizationUrl
        }
        ProvidersAction::CopyOAuth(_, OAuthCopyKind::DeviceCode) => {
            ProvidersFixture::CopyDeviceCode
        }
        ProvidersAction::CopilotConfirm(_, ConfirmationChoice::Confirm) => {
            ProvidersFixture::CopilotConfirm
        }
        ProvidersAction::CopilotConfirm(_, ConfirmationChoice::Cancel) => {
            ProvidersFixture::CopilotCancel
        }
    }
}

fn lsp_edit(edit: LspEdit, save: bool, cancel: bool) -> LspFixture {
    match (edit, save, cancel) {
        (LspEdit::OtherFilesLimit, false, false) => LspFixture::EditOtherFilesLimit,
        (LspEdit::PerFileLimit, false, false) => LspFixture::EditPerFileLimit,
        (LspEdit::DebounceMs, false, false) => LspFixture::EditDebounceMs,
        (LspEdit::DocumentTimeoutMs, false, false) => LspFixture::EditDocumentTimeoutMs,
        (LspEdit::WorkspaceTimeoutMs, false, false) => LspFixture::EditWorkspaceTimeoutMs,
        (LspEdit::OtherFilesLimit, true, false) => LspFixture::SaveOtherFilesLimit,
        (LspEdit::PerFileLimit, true, false) => LspFixture::SavePerFileLimit,
        (LspEdit::DebounceMs, true, false) => LspFixture::SaveDebounceMs,
        (LspEdit::DocumentTimeoutMs, true, false) => LspFixture::SaveDocumentTimeoutMs,
        (LspEdit::WorkspaceTimeoutMs, true, false) => LspFixture::SaveWorkspaceTimeoutMs,
        (LspEdit::OtherFilesLimit, false, true) => LspFixture::CancelOtherFilesLimit,
        (LspEdit::PerFileLimit, false, true) => LspFixture::CancelPerFileLimit,
        (LspEdit::DebounceMs, false, true) => LspFixture::CancelDebounceMs,
        (LspEdit::DocumentTimeoutMs, false, true) => LspFixture::CancelDocumentTimeoutMs,
        (LspEdit::WorkspaceTimeoutMs, false, true) => LspFixture::CancelWorkspaceTimeoutMs,
        (_, true, true) => unreachable!("an LSP edit cannot be save and cancel"),
    }
}

fn lsp_key(action: &LspAction) -> LspFixture {
    match action {
        LspAction::ToggleEnabled => LspFixture::ToggleEnabled,
        LspAction::CycleAutoInstall => LspFixture::CycleAutoInstall,
        LspAction::ToggleDiagnostics => LspFixture::ToggleDiagnostics,
        LspAction::Edit(edit) => lsp_edit(*edit, false, false),
        LspAction::SaveEdit(edit) => lsp_edit(*edit, true, false),
        LspAction::CancelEdit(edit) => lsp_edit(*edit, false, true),
        LspAction::Reset => LspFixture::Reset,
        LspAction::Check(_) => LspFixture::Check,
        LspAction::Install(_) => LspFixture::Install,
        LspAction::Uninstall(_) => LspFixture::Uninstall,
        LspAction::Restart(_) => LspFixture::Restart,
    }
}
