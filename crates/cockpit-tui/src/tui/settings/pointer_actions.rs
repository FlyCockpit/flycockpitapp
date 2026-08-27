//! Sealed semantic action vocabulary for `/settings` pointer surfaces.
//!
//! Geometry uses a small render-local key while it is being assembled, but
//! page contracts and fixtures speak only these identities.  In particular,
//! dynamic rows carry their stable domain identity rather than a cursor.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ImageEndpointId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ImageTargetId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ImageWorkflowId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ImageJobId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct LateResultId(pub String);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum GenerationNodeId {
    Endpoints,
    Targets,
    Workflows,
    Budget,
    Grants,
    Jobs,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum SidecarNodeId {
    Mode,
    Defaults,
    Override,
    CentralPolicy,
    Resolver,
    Health,
    Grants,
    Invocations,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum SidecarModeChoice {
    Automatic,
    Always,
    Never,
}
impl SidecarModeChoice {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Always => "always",
            Self::Never => "never",
        }
    }

    pub(super) fn from_core(mode: cockpit_core::image_sidecar::SidecarMode) -> Self {
        match mode {
            cockpit_core::image_sidecar::SidecarMode::Automatic => Self::Automatic,
            cockpit_core::image_sidecar::SidecarMode::Always => Self::Always,
            cockpit_core::image_sidecar::SidecarMode::Never => Self::Never,
        }
    }

    pub(super) fn to_core(self) -> cockpit_core::image_sidecar::SidecarMode {
        match self {
            Self::Automatic => cockpit_core::image_sidecar::SidecarMode::Automatic,
            Self::Always => cockpit_core::image_sidecar::SidecarMode::Always,
            Self::Never => cockpit_core::image_sidecar::SidecarMode::Never,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SidecarGrantId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SidecarInvocationId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SidecarModelRef {
    pub provider: String,
    pub model: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct AgentId {
    name: String,
    occurrence: String,
}
impl AgentId {
    pub(super) fn workspace(name: &str) -> Self {
        Self {
            name: name.into(),
            occurrence: "workspace:unbound".into(),
        }
    }

    pub(super) fn workspace_occurrence(name: &str, source_identity: &str, revision: &str) -> Self {
        Self {
            name: name.into(),
            occurrence: format!("workspace:{source_identity}:{revision}"),
        }
    }

    pub(super) fn assistant(name: &str) -> Self {
        Self {
            name: name.into(),
            occurrence: "assistant:unbound".into(),
        }
    }

    pub(super) fn assistant_occurrence(name: &str, registration_revision: &str) -> Self {
        Self {
            name: name.into(),
            occurrence: format!("assistant:{registration_revision}"),
        }
    }

    pub(super) fn reset_all() -> Self {
        Self {
            name: "reset-all".into(),
            occurrence: "action:reset-all".into(),
        }
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// Occurrence tokens bind to a workspace's live source identity and
    /// revision, so pointer coverage keys on the stable name form instead.
    #[cfg(test)]
    pub(super) fn canonical_for_coverage(&self) -> Self {
        match self.occurrence.split_once(':') {
            Some(("workspace", _)) => Self::workspace(&self.name),
            Some(("assistant", _)) => Self::assistant(&self.name),
            _ => self.clone(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ProviderId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ModelId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct UserToolId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct McpServerId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct McpToolId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct LspServerId(pub String);
pub(super) type SettingId = super::category::SettingId;
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct UtilityModelId(pub String);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RootNodeId {
    DefaultModel,
    Providers,
    Dependencies,
    Agents,
    Interface,
    Behavior,
    Privacy,
    #[cfg(feature = "extended")]
    ImageSpend,
    Generation,
    ImageSidecar,
    Translation,
    Tools,
    Harnesses,
    Skills,
    Profile,
    Mcp,
    Lsp,
}
impl RootNodeId {
    pub(super) const ALL: &'static [Self] = &[
        Self::DefaultModel,
        Self::Providers,
        Self::Dependencies,
        Self::Agents,
        Self::Interface,
        Self::Behavior,
        Self::Privacy,
        #[cfg(feature = "extended")]
        Self::ImageSpend,
        Self::Generation,
        Self::ImageSidecar,
        Self::Translation,
        Self::Tools,
        Self::Harnesses,
        Self::Skills,
        Self::Profile,
        Self::Mcp,
        Self::Lsp,
    ];
    pub(super) fn title(&self) -> &'static str {
        match self {
            Self::DefaultModel => super::DEFAULT_MODEL_TITLE,
            Self::Providers => super::PROVIDERS_TITLE,
            Self::Dependencies => "Dependencies",
            Self::Agents => "Agents",
            Self::Interface => "Interface",
            Self::Behavior => "Behavior",
            Self::Privacy => "Privacy & Safety",
            #[cfg(feature = "extended")]
            Self::ImageSpend => "Image spend budgets",
            Self::Generation => "Generation",
            Self::ImageSidecar => "Image Sidecar",
            Self::Translation => "Translation",
            Self::Tools => "Tools",
            Self::Harnesses => "Harnesses",
            Self::Skills => "Skills",
            Self::Profile => "Profile",
            Self::Mcp => "MCP",
            Self::Lsp => "LSP",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SuggestionId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct PickerOptionId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct AgentToolId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct HarnessId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ScanDirectoryId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ListRowId {
    pub kind: ListKind,
    pub index: usize,
    pub value: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ListKind {
    Instructions,
    RedactPatterns,
    String(super::string_list::StringListKind),
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct HeaderName(pub String);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum HarnessField {
    Command,
    Args,
    PromptInput,
    ArgvOverflow,
    ModelArgs,
    DefaultModel,
    Models,
    ModelListArgs,
    SupportsJson,
    JsonOutputArgs,
    SupportsAgentFile,
    AgentFileArgs,
    AgentFileEnv,
    Trust,
    AuthProbeArgs,
    Timeout,
    AlwaysAllow,
}
impl HarnessField {
    pub(super) const ALL: [Self; 17] = [
        Self::Command,
        Self::Args,
        Self::PromptInput,
        Self::ArgvOverflow,
        Self::ModelArgs,
        Self::DefaultModel,
        Self::Models,
        Self::ModelListArgs,
        Self::SupportsJson,
        Self::JsonOutputArgs,
        Self::SupportsAgentFile,
        Self::AgentFileArgs,
        Self::AgentFileEnv,
        Self::Trust,
        Self::AuthProbeArgs,
        Self::Timeout,
        Self::AlwaysAllow,
    ];
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ToolFieldId {
    FirecrawlBaseUrl,
    WebFetchCommand,
    WebSearchCommand,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct BuiltinToolId(pub String);
pub(super) type WizardStepId = cockpit_core::wizard::ProviderWizardStep;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum WizardAuthMethod {
    PasteKey,
    EnvVar,
    AdvancedHeaders,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum WizardTestChoice {
    TestKey,
    SkipTest,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum WizardControlId {
    Template(String),
    AuthMethod(WizardAuthMethod),
    TestChoice(WizardTestChoice),
    OAuth(super::providers::OAuthOption),
    Header(HeaderName),
    AddHeader,
    ContinueHeaders,
    CopilotContinue,
    TestSkippedContinue,
    DoneContinue,
    EditText,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct OAuthFlowId(pub u128);

impl OAuthFlowId {
    /// Stable owner idempotency key for acknowledgement retries in this pane.
    pub(crate) fn subscription_ack_operation_id(self) -> String {
        format!("subscription-ack-{:032x}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ConfirmationChoice {
    Confirm,
    Cancel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ExternalEditOutcome {
    Saved,
    Cancelled,
    Failed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum CategoryExternalSource {
    Cursor,
    Inline,
    PathEditor,
    TextEditor,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum CredentialKind {
    Firecrawl,
    TinyFish,
}
impl CredentialKind {
    pub(super) const ALL: [Self; 2] = [Self::Firecrawl, Self::TinyFish];
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum LspEdit {
    OtherFilesLimit,
    PerFileLimit,
    DebounceMs,
    DocumentTimeoutMs,
    WorkspaceTimeoutMs,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum FetchAllChoice {
    Apply,
    Cancel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum FetchOneChoice {
    Apply,
    KeepLocal,
    Cancel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum FetchFallbackChoice {
    Retry,
    KeepLocal,
    UseFallback,
    Cancel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum DeepFetchChoice {
    Fetch,
    Cancel,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum ModelLifecycleAction {
    Refresh(ProviderId, ModelId),
    Discard(ProviderId, ModelId),
    Retry(ProviderId, ModelId),
    Reload(ProviderId, ModelId),
    Reapply(ProviderId, ModelId),
    Rebind(ProviderId, ModelId),
    Dismiss(ProviderId, ModelId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum SettingsPointerAction {
    Root(RootAction),
    Category(CategoryAction),
    Agents(AgentsAction),
    Tools(ToolsAction),
    Harnesses(HarnessesAction),
    Skills(SkillsAction),
    Mcp(McpAction),
    Providers(ProvidersAction),
    Lsp(LspAction),
    List(ListAction),
    UtilityModel(UtilityModelAction),
    DefaultModel(DefaultModelAction),
    Generation(GenerationAction),
    Sidecar(SidecarAction),
}

impl From<HarnessesAction> for SettingsPointerAction {
    fn from(action: HarnessesAction) -> Self {
        Self::Harnesses(action)
    }
}

impl From<McpAction> for SettingsPointerAction {
    fn from(action: McpAction) -> Self {
        Self::Mcp(action)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum RootAction {
    Open(RootNodeId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum CategoryAction {
    DescriptorActivate(SettingId),
    InlineEditBegin(SettingId),
    InlineEditCommit(SettingId),
    InlineEditCancel(SettingId),
    PathEditBegin(SettingId),
    PathEditCommit(SettingId),
    PathEditCancel(SettingId),
    SuggestionSelect(SettingId, SuggestionId),
    TextEditorSave(SettingId),
    TextEditorCancel(SettingId),
    PickerSelect(SettingId, PickerOptionId),
    Confirm(SettingId, ConfirmationChoice),
    Reset,
    ExternalEditBegin(SettingId, CategoryExternalSource),
    ExternalEditResult(SettingId, ExternalEditOutcome),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum AgentsAction {
    Open(AgentId),
    Edit(AgentId),
    Delete(AgentId),
    Reset(AgentId),
    ResetAll,
    ToggleTool(AgentId, AgentToolId),
    CycleTier(AgentId, AgentToolId),
    Save(AgentId),
    OpenRawEditor(AgentId),
    EditText(AgentId),
    Cancel(AgentId),
    ExternalEditBegin(AgentId),
    ExternalEditResult(AgentId, ExternalEditOutcome),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum ToolsAction {
    CycleWebProvider,
    EditFirecrawlBaseUrl,
    EditCredential(CredentialKind),
    EditWebFetchCommand,
    EditWebSearchCommand,
    EditUserToolCommand(UserToolId),
    AddUserTool,
    ToggleUserTool(UserToolId),
    ResetToolField(ToolFieldId),
    McpJump,
    Reset,
    DeleteUserTool(UserToolId),
    ReadOnlyBuiltin(BuiltinToolId),
    ReadOnlyMcpTool(McpServerId, McpToolId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum HarnessesAction {
    Open(HarnessId),
    Add,
    Delete(HarnessId),
    SeedInstalledPresets,
    ResetAndSeedPresets,
    EditField(HarnessField),
    Save,
    Cancel,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum SkillsAction {
    ToggleAutoBangCommands,
    ToggleAncestorWalk,
    AddScanDirectory,
    EditScanDirectory(ScanDirectoryId),
    DeleteScanDirectory(ScanDirectoryId),
    ConfirmDeleteScanDirectory(ScanDirectoryId, ConfirmationChoice),
    Reset,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum McpAction {
    Open(McpServerId),
    Add,
    ToggleEnabled(McpServerId),
    Authenticate(McpServerId),
    Delete(McpServerId),
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
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ProviderDeleteChoice {
    RemoveSecrets,
    KeepSecrets,
    Cancel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum OAuthCopyKind {
    AuthorizationUrl,
    DeviceCode,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum ProvidersAction {
    Open(ProviderId),
    Add,
    EditField(ProviderId, super::providers::EditField),
    EditHeaders(ProviderId),
    CopilotSetup(ProviderId),
    BeginOAuth(ProviderId, super::providers::OAuthProvider),
    OAuthOption(ProviderId, super::providers::OAuthOption),
    ManageModels(ProviderId),
    ProviderSettings(ProviderId),
    Favorite(ProviderId),
    Refetch(ProviderId),
    RefetchAll,
    CycleUnlistedPolicy,
    DeepFetchConfirm(ProviderId),
    BeginDelete(ProviderId),
    Delete(ProviderId, ProviderDeleteChoice),
    SaveProvider(ProviderId),
    LocalBack,
    AddModel(ProviderId),
    RenameModel(ProviderId, ModelId),
    DeleteModel(ProviderId, ModelId),
    ModelSettings(ProviderId, ModelId),
    FetchAllConfirm(FetchAllChoice),
    FetchOneConfirm(ProviderId, FetchOneChoice),
    FetchFallbackConfirm(ProviderId, FetchFallbackChoice),
    DeepFetchChoice(ProviderId, DeepFetchChoice),
    WizardControl(WizardStepId, WizardControlId),
    /// A control published by a provider row editor.  Every identity comes
    /// from the rendered domain object; cursor ordinals never cross the hit
    /// map/reducer boundary.
    RowEditor(ProviderRowEditorAction),
    ModelLifecycle(ModelLifecycleAction),
    CopyOAuth(OAuthFlowId, OAuthCopyKind),
    CopilotConfirm(ProviderId, ConfirmationChoice),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum ProviderRowEditorAction {
    HeaderOpen(HeaderName),
    HeaderAdd,
    HeaderSave,
    ModelOpen(ModelId),
    ModelAdd,
    ModelSave,
    SettingEdit(super::settings_editor::ProviderSettingId),
    SettingSave,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum LspAction {
    ToggleEnabled,
    CycleAutoInstall,
    ToggleDiagnostics,
    Edit(LspEdit),
    SaveEdit(LspEdit),
    CancelEdit(LspEdit),
    Reset,
    Check(LspServerId),
    Install(LspServerId),
    Uninstall(LspServerId),
    Restart(LspServerId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum ListAction {
    Add,
    Edit(ListRowId),
    Delete(ListRowId),
    MoveUp(ListRowId),
    MoveDown(ListRowId),
    Save,
    Cancel,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum UtilityModelAction {
    Select(UtilityModelId),
    Clear,
    OpenCustom,
    Back,
    EditCustom,
    CommitCustom,
    CancelCustom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DefaultModelAction {
    Choose,
    Clear,
}

/// Sealed image-generation settings action vocabulary.
///
/// Each named settings state action is visible, disabled with a stable
/// reason, or intentionally non-action; no keyboard-only action is allowed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum GenerationAction {
    /// Open a Generation sub-node from the list page.
    OpenNode(GenerationNodeId),
    /// Refresh target health (admin-gated action).
    RefreshHealth,
    // Endpoint CRUD
    CreateEndpoint,
    EditEndpoint(ImageEndpointId),
    DeleteEndpoint(ImageEndpointId),
    // Target CRUD + default
    CreateTarget,
    EditTarget(ImageTargetId),
    DeleteTarget(ImageTargetId),
    SetDefaultTarget(ImageTargetId),
    // Workflow upload/bind/delete
    UploadWorkflow,
    BindWorkflow(ImageWorkflowId),
    DeleteWorkflow(ImageWorkflowId),
    // Budget save
    SaveBudget,
    // Grant revoke
    RevokeGrant(LateResultId),
    // Job cancel
    CancelJob(ImageJobId),
    // Late result publish/discard (entered from JobDetail)
    PublishLateResult(LateResultId),
    DiscardLateResult(LateResultId),
    // Confirmation choices for destructive actions
    ConfirmCancelJob(ImageJobId, ConfirmationChoice),
    ConfirmRevokeGrant(LateResultId, ConfirmationChoice),
    ConfirmPublishLateResult(LateResultId, ConfirmationChoice),
    ConfirmDiscardLateResult(LateResultId, ConfirmationChoice),
    // Cancel/back from an editor
    Cancel,
}

/// Sealed image-sidecar settings action vocabulary.
///
/// Named actions: set mode/default/override, clear override, save central
/// policy, refresh health, create grant, revoke grant, and open
/// resolver/invocation detail. Each is visible, disabled with a stable
/// reason, or intentionally non-action; no keyboard-only action is allowed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum SidecarAction {
    OpenNode(SidecarNodeId),
    SetMode(SidecarModeChoice),
    SetTrustedDefault(SidecarModelRef),
    SetUntrustedDefault(SidecarModelRef),
    SetOverride(SidecarModelRef),
    ClearOverride,
    SaveCentralPolicy,
    RefreshHealth,
    CreateGrant,
    SelectGrantScope(cockpit_core::image_sidecar::GrantScope),
    RevokeGrant(SidecarGrantId),
    ConfirmRevokeGrant(SidecarGrantId, ConfirmationChoice),
    OpenResolverDetail,
    OpenHealthDetail,
    OpenGrantEditor,
    OpenInvocationDetail(SidecarInvocationId),
    Cancel,
}

impl From<GenerationAction> for SettingsPointerAction {
    fn from(action: GenerationAction) -> Self {
        Self::Generation(action)
    }
}

impl From<SidecarAction> for SettingsPointerAction {
    fn from(action: SidecarAction) -> Self {
        Self::Sidecar(action)
    }
}

impl SettingsPointerAction {
    pub(crate) fn is_button(&self) -> bool {
        !self.is_row_control()
    }

    pub(crate) fn is_row_control(&self) -> bool {
        match self {
            Self::Root(RootAction::Open(_)) => true,
            Self::Category(action) => matches!(
                action,
                CategoryAction::DescriptorActivate(_)
                    | CategoryAction::InlineEditBegin(_)
                    | CategoryAction::PathEditBegin(_)
                    | CategoryAction::SuggestionSelect(_, _)
                    | CategoryAction::PickerSelect(_, _)
            ),
            Self::Agents(action) => matches!(
                action,
                AgentsAction::Open(_)
                    | AgentsAction::ToggleTool(_, _)
                    | AgentsAction::CycleTier(_, _)
            ),
            Self::Tools(action) => matches!(
                action,
                ToolsAction::ReadOnlyBuiltin(_) | ToolsAction::ReadOnlyMcpTool(_, _)
            ),
            Self::Harnesses(action) => {
                matches!(
                    action,
                    HarnessesAction::Open(_) | HarnessesAction::EditField(_)
                )
            }
            Self::Skills(action) => matches!(action, SkillsAction::EditScanDirectory(_)),
            Self::Mcp(action) => matches!(
                action,
                McpAction::Open(_)
                    | McpAction::ToggleEnabled(_)
                    | McpAction::EditName
                    | McpAction::ToggleEditorEnabled
                    | McpAction::CycleTransport
                    | McpAction::EditEndpoint
                    | McpAction::EditCommand
                    | McpAction::EditArgs
                    | McpAction::EditBaseEnv
                    | McpAction::CycleAuth
                    | McpAction::EditHeaderName
                    | McpAction::EditHeaderValue
                    | McpAction::EditAuthEnv
                    | McpAction::EditOauthAuthorizeUrl
                    | McpAction::EditOauthTokenUrl
                    | McpAction::EditOauthClientId
                    | McpAction::EditOauthScopes
                    | McpAction::EditCacheTtl
                    | McpAction::EditConnectTimeout
                    | McpAction::EditRequestTimeout
            ),
            Self::Providers(action) => matches!(
                action,
                ProvidersAction::Open(_)
                    | ProvidersAction::EditField(_, _)
                    | ProvidersAction::OAuthOption(_, _)
                    | ProvidersAction::WizardControl(_, _)
                    | ProvidersAction::FetchAllConfirm(_)
                    | ProvidersAction::FetchOneConfirm(_, _)
                    | ProvidersAction::FetchFallbackConfirm(_, _)
                    | ProvidersAction::DeepFetchChoice(_, _)
                    | ProvidersAction::RowEditor(
                        ProviderRowEditorAction::HeaderOpen(_)
                            | ProviderRowEditorAction::ModelOpen(_)
                            | ProviderRowEditorAction::SettingEdit(_),
                    )
            ),
            Self::Lsp(action) => matches!(
                action,
                LspAction::ToggleEnabled
                    | LspAction::CycleAutoInstall
                    | LspAction::ToggleDiagnostics
                    | LspAction::Edit(_)
            ),
            Self::List(action) => matches!(action, ListAction::Edit(_)),
            Self::UtilityModel(action) => matches!(action, UtilityModelAction::Select(_)),
            Self::DefaultModel(_) => false,
            Self::Generation(action) => matches!(
                action,
                GenerationAction::OpenNode(_)
                    | GenerationAction::EditEndpoint(_)
                    | GenerationAction::EditTarget(_)
            ),
            Self::Sidecar(action) => matches!(action, SidecarAction::OpenNode(_)),
        }
    }

    pub(crate) fn button_label(&self) -> Option<&'static str> {
        if !self.is_button() {
            return None;
        }
        Some(match self {
            Self::DefaultModel(DefaultModelAction::Choose) => "Choose default model",
            Self::DefaultModel(DefaultModelAction::Clear) => "Clear default for this scope",
            Self::Category(CategoryAction::InlineEditCommit(_))
            | Self::Category(CategoryAction::PathEditCommit(_))
            | Self::Category(CategoryAction::TextEditorSave(_)) => "Save",
            Self::Category(CategoryAction::InlineEditCancel(_))
            | Self::Category(CategoryAction::PathEditCancel(_))
            | Self::Category(CategoryAction::TextEditorCancel(_)) => "Cancel",
            Self::Category(CategoryAction::Reset) => "reset to defaults",
            Self::Category(CategoryAction::Confirm(_, ConfirmationChoice::Confirm)) => "confirm",
            Self::Category(CategoryAction::Confirm(_, ConfirmationChoice::Cancel)) => "Cancel",
            Self::Category(CategoryAction::ExternalEditBegin(_, _)) => "Open in $EDITOR",
            Self::Agents(AgentsAction::Edit(_)) => "Edit",
            Self::Agents(AgentsAction::Delete(_)) => "Delete",
            Self::Agents(AgentsAction::Reset(_)) => "Reset",
            Self::Agents(AgentsAction::ResetAll) => "Reset all",
            Self::Agents(AgentsAction::Save(_)) => "Save",
            Self::Agents(AgentsAction::Cancel(_)) => "Cancel",
            Self::Agents(AgentsAction::OpenRawEditor(_)) => "Edit raw file",
            Self::Agents(AgentsAction::ExternalEditBegin(_)) => "Open in $EDITOR",
            Self::Tools(ToolsAction::AddUserTool) => "Add",
            Self::Tools(ToolsAction::Reset) => "reset to defaults",
            Self::Tools(ToolsAction::McpJump) => "MCP",
            Self::Harnesses(HarnessesAction::Add) => "Add",
            Self::Harnesses(HarnessesAction::Save) => "Save",
            Self::Harnesses(HarnessesAction::Cancel) => "Cancel",
            Self::Skills(SkillsAction::AddScanDirectory) => "Add",
            Self::Skills(SkillsAction::Reset) => "reset to defaults",
            Self::Mcp(McpAction::Add) => "Add",
            Self::Mcp(McpAction::Save) => "save",
            Self::Mcp(McpAction::Cancel) => "Cancel",
            Self::Providers(ProvidersAction::Add) => "Add",
            Self::Providers(ProvidersAction::SaveProvider(_)) => "save changes",
            Self::Providers(ProvidersAction::LocalBack) => "Back",
            Self::Providers(ProvidersAction::AddModel(_)) => "Add model",
            Self::Lsp(LspAction::SaveEdit(_)) => "Save",
            Self::Lsp(LspAction::CancelEdit(_)) => "Cancel",
            Self::Lsp(LspAction::Reset) => "reset to defaults",
            Self::List(ListAction::Add) => "Add",
            Self::List(ListAction::Save) => "Save",
            Self::List(ListAction::Cancel) => "Cancel",
            Self::List(ListAction::Delete(_)) => "Delete",
            Self::UtilityModel(UtilityModelAction::Clear) => "clear — unset",
            Self::UtilityModel(UtilityModelAction::Back) => "Back",
            Self::UtilityModel(UtilityModelAction::CommitCustom) => "Save custom",
            Self::UtilityModel(UtilityModelAction::CancelCustom) => "Cancel",
            Self::Generation(GenerationAction::Cancel) => "Cancel",
            Self::Generation(GenerationAction::SaveBudget) => "Save",
            Self::Generation(GenerationAction::RefreshHealth) => "refresh health",
            Self::Generation(GenerationAction::CreateEndpoint) => "create endpoint",
            Self::Generation(GenerationAction::DeleteEndpoint(_)) => "delete endpoint",
            Self::Generation(GenerationAction::CreateTarget) => "create target",
            Self::Generation(GenerationAction::DeleteTarget(_)) => "delete target",
            Self::Generation(GenerationAction::SetDefaultTarget(_)) => "set default",
            Self::Generation(GenerationAction::UploadWorkflow) => "upload workflow",
            Self::Generation(GenerationAction::BindWorkflow(_)) => "bind workflow",
            Self::Generation(GenerationAction::DeleteWorkflow(_)) => "delete workflow",
            Self::Generation(GenerationAction::RevokeGrant(_)) => "revoke grant",
            Self::Generation(GenerationAction::CancelJob(_)) => "cancel job",
            Self::Generation(GenerationAction::PublishLateResult(_)) => "publish late result",
            Self::Generation(GenerationAction::DiscardLateResult(_)) => "discard late result",
            Self::Generation(GenerationAction::ConfirmCancelJob(
                _,
                ConfirmationChoice::Confirm,
            )) => "Cancel job",
            Self::Generation(GenerationAction::ConfirmRevokeGrant(
                _,
                ConfirmationChoice::Confirm,
            )) => "Revoke grant",
            Self::Generation(GenerationAction::ConfirmPublishLateResult(
                _,
                ConfirmationChoice::Confirm,
            )) => "Publish",
            Self::Generation(GenerationAction::ConfirmDiscardLateResult(
                _,
                ConfirmationChoice::Confirm,
            )) => "Discard",
            Self::Generation(
                GenerationAction::ConfirmCancelJob(_, ConfirmationChoice::Cancel)
                | GenerationAction::ConfirmRevokeGrant(_, ConfirmationChoice::Cancel)
                | GenerationAction::ConfirmPublishLateResult(_, ConfirmationChoice::Cancel)
                | GenerationAction::ConfirmDiscardLateResult(_, ConfirmationChoice::Cancel),
            ) => "Cancel",
            Self::Sidecar(SidecarAction::SetMode(SidecarModeChoice::Automatic)) => "automatic",
            Self::Sidecar(SidecarAction::SetMode(SidecarModeChoice::Always)) => "always",
            Self::Sidecar(SidecarAction::SetMode(SidecarModeChoice::Never)) => "never",
            Self::Sidecar(SidecarAction::SetTrustedDefault(_)) => "set trusted default",
            Self::Sidecar(SidecarAction::SetUntrustedDefault(_)) => "set untrusted default",
            Self::Sidecar(SidecarAction::SetOverride(_)) => "set override",
            Self::Sidecar(SidecarAction::ClearOverride) => "clear override",
            Self::Sidecar(SidecarAction::SaveCentralPolicy) => "Save",
            Self::Sidecar(SidecarAction::RefreshHealth) => "refresh health",
            Self::Sidecar(SidecarAction::CreateGrant) => "create grant",
            Self::Sidecar(SidecarAction::SelectGrantScope(
                cockpit_core::image_sidecar::GrantScope::Once,
            )) => "once",
            Self::Sidecar(SidecarAction::SelectGrantScope(
                cockpit_core::image_sidecar::GrantScope::Session,
            )) => "session",
            Self::Sidecar(SidecarAction::SelectGrantScope(
                cockpit_core::image_sidecar::GrantScope::Project,
            )) => "project",
            Self::Sidecar(SidecarAction::RevokeGrant(_)) => "revoke grant",
            Self::Sidecar(SidecarAction::ConfirmRevokeGrant(_, ConfirmationChoice::Confirm)) => {
                "Revoke grant"
            }
            Self::Sidecar(SidecarAction::ConfirmRevokeGrant(_, ConfirmationChoice::Cancel)) => {
                "Cancel"
            }
            Self::Sidecar(SidecarAction::OpenResolverDetail) => "open resolver detail",
            Self::Sidecar(SidecarAction::OpenHealthDetail) => "open health detail",
            Self::Sidecar(SidecarAction::OpenGrantEditor) => "open grant editor",
            Self::Sidecar(SidecarAction::OpenInvocationDetail(_)) => "open invocation detail",
            Self::Sidecar(SidecarAction::Cancel) => "Cancel",
            _ => "action",
        })
    }
}
