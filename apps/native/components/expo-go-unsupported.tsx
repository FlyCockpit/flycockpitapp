/**
 * Expo Go unsupported state for the native WebRTC remote client.
 *
 * @see prompts/flycockpitapp/ready/remote-webrtc-native-client.md
 * Acceptance criterion 10: Expo Go UX.
 *
 * Expo Go is intentionally unsupported because `react-native-webrtc` requires
 * a development/production build. Expo Go renders an explicit
 * development-build-required state.
 */
import Constants from "expo-constants";
import { Text, View } from "react-native";

export interface ExpoGoUnsupportedProps {
  readonly message?: string;
}

/**
 * Returns true if the current execution context is Expo Go. Expo Go cannot
 * load native modules like `react-native-webrtc`.
 */
export function isExpoGo(): boolean {
  return Constants.executionEnvironment === "storeClient";
}

/**
 * Renders the explicit development-build-required state for Expo Go. This is
 * not a silent disappearance — it is a clear, actionable message.
 */
export function ExpoGoUnsupported({ message }: ExpoGoUnsupportedProps) {
  const text =
    message ??
    "WebRTC remote access requires a development or production build. Expo Go is not supported.";
  return (
    <View style={{ padding: 24, alignItems: "center" }}>
      <Text>{text}</Text>
    </View>
  );
}
