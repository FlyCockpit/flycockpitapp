//! Sealed semantic action vocabulary for `/settings` pointer surfaces.
//!
//! Geometry uses a small render-local key while it is being assembled, but
//! page contracts and fixtures speak only these identities.  In particular,
//! dynamic rows carry their stable domain identity rather than a cursor.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct AgentId(pub String);
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct SettingId(pub u64);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct UtilityModelId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct RootNodeId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct StableRowId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ToolFieldId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct BuiltinToolId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct WizardStepId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct WizardControlId(pub String);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct OAuthFlowId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ConfirmationChoice {
    Confirm,
    Cancel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ExternalEditOutcome {
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
    Cancel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum DeepFetchChoice {
    Fetch,
    Cancel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ModelLifecycleAction {
    Refresh,
    Discard,
    Retry,
    Reload,
    Reapply,
    Rebind,
    Dismiss,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum SettingsPointerAction {
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
}

impl From<super::shell::SettingsControlId> for SettingsPointerAction {
    fn from(value: super::shell::SettingsControlId) -> Self {
        Self::Providers(ProvidersAction::RowEditor(
            StableRowId("provider-page".to_string()),
            StableRowId("control".to_string()),
            StableRowId(value.0.to_string()),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum RootAction {
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
    SuggestionSelect(SettingId, StableRowId),
    TextEditorSave(SettingId),
    TextEditorCancel(SettingId),
    PickerSelect(SettingId, StableRowId),
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
    ToggleTool(AgentId, StableRowId),
    CycleTier(AgentId, StableRowId),
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
    Open(StableRowId),
    Add,
    Delete(StableRowId),
    SeedInstalledPresets,
    ResetAndSeedPresets,
    EditField(StableRowId),
    Save,
    Cancel,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum SkillsAction {
    ToggleAutoBangCommands,
    ToggleAncestorWalk,
    AddScanDirectory,
    EditScanDirectory(StableRowId),
    DeleteScanDirectory(StableRowId),
    ConfirmDeleteScanDirectory(StableRowId, ConfirmationChoice),
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
    EditField(ProviderId, StableRowId),
    EditHeaders(ProviderId),
    CopilotSetup(ProviderId),
    OAuthSetup(ProviderId, StableRowId),
    ManageModels(ProviderId),
    ProviderSettings(ProviderId),
    Favorite(ProviderId),
    Refetch(ProviderId),
    RefetchAll,
    CycleUnlistedPolicy,
    DeepFetchConfirm(ProviderId, StableRowId),
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
    RowEditor(StableRowId, StableRowId, StableRowId),
    ModelLifecycle(ModelLifecycleAction),
    CopyOAuth(OAuthFlowId, OAuthCopyKind),
    CopilotConfirm(ProviderId, ConfirmationChoice),
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
    Edit(StableRowId),
    Delete(StableRowId),
    MoveUp(StableRowId),
    MoveDown(StableRowId),
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
pub(super) enum DefaultModelAction {
    Choose,
    Clear,
}
