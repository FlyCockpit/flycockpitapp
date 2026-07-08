import { useUserNotifications } from "@/hooks/use-user-notifications";

export function UserNotificationClient() {
  useUserNotifications();
  return null;
}
