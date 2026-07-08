import { AsyncLocalStorage } from "node:async_hooks";

type UserCreationMode = "admin-bootstrap" | "admin-invite";

const userCreationModeStorage = new AsyncLocalStorage<UserCreationMode>();

export function getAllowedUserCreationMode(): UserCreationMode | undefined {
  return userCreationModeStorage.getStore();
}

export function runWithAllowedUserCreation<T>(
  mode: UserCreationMode,
  fn: () => T | Promise<T>,
): T | Promise<T> {
  return userCreationModeStorage.run(mode, fn);
}
