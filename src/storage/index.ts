export {
  ensureDir,
  readJSON,
  writeJSON,
  writeFileAtomic,
  withLock,
} from "./engine.js";

export {
  resolveDataDir,
  getEngagementDir,
  getMetadataPath,
  getState,
  setState,
  getActiveEngagementId,
  setActiveEngagement,
  clearActiveEngagement,
  requireActiveEngagement,
  getIndex,
  updateIndexEntry,
  removeIndexEntry,
} from "./state.js";
