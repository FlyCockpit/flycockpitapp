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
    ResetToolField(StableRowId),
    McpJump,
    Reset,
    DeleteUserTool(UserToolId),
    ReadOnlyBuiltin(StableRowId),
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
    Reset,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum McpAction {
    Open(McpServerId),
    Add,
    ToggleEnabled(McpServerId),
    Authenticate(McpServerId),
    Delete(McpServerId),
    EditField(StableRowId),
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
    WizardControl(StableRowId, StableRowId),
    RowEditor(StableRowId, StableRowId, StableRowId),
    ModelLifecycle(StableRowId),
    CopyOAuth(ProviderId, OAuthCopyKind),
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
