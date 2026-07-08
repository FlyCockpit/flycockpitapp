import { Button } from "@flycockpit/ui/components/button";
import {
  Popover,
  PopoverContent,
  PopoverHeader,
  PopoverTitle,
  PopoverTrigger,
} from "@flycockpit/ui/components/popover";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useDeferredSession } from "@/stores/session";
import { orpc } from "@/utils/orpc";

export function NotificationInbox() {
  const { t } = useTranslation("common");
  const session = useDeferredSession();
  const signedIn = Boolean(session.data?.user);
  const queryClient = useQueryClient();
  const list = useQuery({
    ...orpc.notifications.listMine.queryOptions({ input: { limit: 10 } }),
    enabled: signedIn,
  });
  const unread = useQuery({
    ...orpc.notifications.unreadCount.queryOptions(),
    enabled: signedIn,
  });
  const markRead = useMutation(
    orpc.notifications.markRead.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.notifications.key() });
      },
    }),
  );

  if (!signedIn) return null;

  const count = unread.data?.count ?? 0;

  return (
    <Popover>
      <PopoverTrigger
        render={
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="relative"
            aria-label={t("notifications.openInbox")}
          />
        }
      >
        <Bell className="size-4" />
        {count > 0 ? (
          <span className="absolute -top-1 -right-1 min-w-4 rounded-full bg-primary px-1 text-[10px] text-primary-foreground tabular-nums">
            {count > 9 ? "9+" : count}
          </span>
        ) : null}
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 max-w-[calc(100vw-1rem)]">
        <PopoverHeader>
          <PopoverTitle>{t("notifications.inbox")}</PopoverTitle>
        </PopoverHeader>
        <div className="max-h-96 overflow-y-auto">
          {list.isPending ? (
            <p className="px-1 py-6 text-center text-muted-foreground">
              {t("notifications.loading")}
            </p>
          ) : list.data?.notifications.length ? (
            <div className="space-y-1">
              {list.data.notifications.map((notification) => (
                <button
                  type="button"
                  key={notification.id}
                  className="w-full rounded-md px-2 py-2 text-left hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  onClick={() => {
                    markRead.mutate({ notificationId: notification.id });
                    window.location.assign(notification.deepLinkUrl);
                  }}
                >
                  <span className="flex items-start gap-2">
                    <span
                      className={
                        notification.readAt
                          ? "mt-1.5 size-1.5 rounded-full bg-transparent"
                          : "mt-1.5 size-1.5 rounded-full bg-primary"
                      }
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-medium text-sm">
                        {notification.title}
                      </span>
                      {notification.body ? (
                        <span className="line-clamp-2 text-muted-foreground">
                          {notification.body}
                        </span>
                      ) : null}
                      {notification.resolvedAt ? (
                        <span className="mt-1 block text-muted-foreground">
                          {t("notifications.resolved")}
                        </span>
                      ) : null}
                    </span>
                  </span>
                </button>
              ))}
            </div>
          ) : (
            <p className="px-1 py-6 text-center text-muted-foreground">
              {t("notifications.empty")}
            </p>
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}
