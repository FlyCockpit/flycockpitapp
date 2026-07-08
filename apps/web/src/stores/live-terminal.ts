import { create } from "zustand";

type LiveTerminal = {
  id: string;
  instanceId: string;
  instanceName: string;
};

type LiveTerminalState = {
  terminals: LiveTerminal[];
  register: (terminal: LiveTerminal) => void;
  unregister: (id: string) => void;
};

export const useLiveTerminalStore = create<LiveTerminalState>()((set) => ({
  terminals: [],
  register: (terminal) =>
    set((state) => ({
      terminals: [terminal, ...state.terminals.filter((item) => item.id !== terminal.id)],
    })),
  unregister: (id) =>
    set((state) => ({ terminals: state.terminals.filter((terminal) => terminal.id !== id) })),
}));
