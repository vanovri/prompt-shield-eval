export {
  createAegisAuditSinkBridge,
  createMcpGuardrailMiddleware,
  MCP_JSONRPC_INVALID_PARAMS,
  MCP_JSONRPC_POLICY_VIOLATION,
  type AegisAuditChainLike,
  type EgressDecision,
  type IngressDecision,
  type McpGuardrailConfig,
  type McpGuardrailMiddleware,
  type McpSecurityAuditEvent,
  type McpToolContentResponse,
  type ToolCallMeta,
  type WrappedToolResult,
} from "./middleware.js";

export {
  AEGIS_TAINTING_TOOLS,
  AEGIS_TOOL_POLICIES,
  createAegisGuardrailMiddleware,
  issueAegisHitlToken,
  verifyAegisHitlToken,
  type AegisGuardrailOptions,
} from "./aegis-preset.js";
