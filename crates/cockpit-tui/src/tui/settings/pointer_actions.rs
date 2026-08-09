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
pub(super) type SettingId = super::category::SettingId;
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct UtilityModelId(pub String);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum RootNodeId {
    DefaultModel,
    Providers,
    Dependencies,
    Agents,
    Interface,
    Behavior,
    Privacy,
    Translation,
    Tools,
    Harnesses,
    Skills,
    Profile,
    Mcp,
    Lsp,
}
impl RootNodeId {
    pub(super) const ALL: [Self; 13] = [
        Self::DefaultModel,
        Self::Providers,
        Self::Agents,
        Self::Interface,
        Self::Behavior,
        Self::Privacy,
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
    AuthEnvVars,
    AuthProbeArgs,
    Timeout,
    AlwaysAllow,
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
    EditText,
}
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
    UseFallback,
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
    SuggestionSelect(SettingId, SuggestionId),
    TextEditorSave(SettingId),
    TextEditorCancel(SettingId),
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
    HeaderContinue,
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
pub(super) enum DefaultModelAction {
    Choose,
    Clear,
}
