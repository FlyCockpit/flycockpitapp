import { Ionicons } from "@expo/vector-icons";
import { Tabs } from "expo-router";
import { useThemeColor } from "heroui-native";

import { ThemeToggle } from "@/components/theme-toggle";

export default function TabLayout() {
  const foregroundColor = useThemeColor("foreground");
  const backgroundColor = useThemeColor("background");
  const mutedColor = useThemeColor("muted");

  return (
    <Tabs
      screenOptions={{
        headerTintColor: foregroundColor,
        headerStyle: { backgroundColor },
        headerTitleStyle: {
          color: foregroundColor,
          fontWeight: "600",
        },
        headerRight: () => <ThemeToggle />,
        tabBarActiveTintColor: foregroundColor,
        tabBarInactiveTintColor: mutedColor,
        tabBarStyle: {
          backgroundColor,
          borderTopColor: mutedColor,
        },
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: "Instances",
          tabBarIcon: ({ color, size }) => (
            <Ionicons name="terminal-outline" size={size} color={color} />
          ),
        }}
      />
      <Tabs.Screen
        name="account"
        options={{
          title: "Account",
          tabBarIcon: ({ color, size }) => (
            <Ionicons name="person-circle-outline" size={size} color={color} />
          ),
        }}
      />
    </Tabs>
  );
}
