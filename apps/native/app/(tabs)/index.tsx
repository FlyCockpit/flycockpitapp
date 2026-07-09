import { Ionicons } from "@expo/vector-icons";
import { env } from "@flycockpit/env/native";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useRouter } from "expo-router";
import { Button, Card, Chip, Input, Spinner, Surface, TextField, useToast } from "heroui-native";
import { useEffect, useState } from "react";
import { Pressable, RefreshControl, Text, View } from "react-native";
import { Container } from "@/components/container";
import { authClient } from "@/lib/auth-client";
import { registerNativePushToken } from "@/utils/native-push";
import { orpc, queryClient } from "@/utils/orpc";
import { type ServerEligibilityResult, verifyServerEligibility } from "@/utils/server-eligibility";

type InstanceCardProps = {
  instance: { id: string; displayName: string; hostname: string; presence: string };
  shared?: boolean;
  onOpen: () => void;
  onRevoke?: () => void;
  onRename?: (displayName: string) => void;
};

function presenceColor(presence: string) {
  if (presence === "online") return "success" as const;
  if (presence === "revoked") return "danger" as const;
  return "default" as const;
}

function InstanceCard({ instance, shared, onOpen, onRevoke, onRename }: InstanceCardProps) {
  const [renameValue, setRenameValue] = useState(instance.displayName);
  const canRename = Boolean(
    onRename && renameValue.trim() && renameValue.trim() !== instance.displayName,
  );

  return (
    <Card variant="secondary" className="p-4">
      <Pressable onPress={onOpen} className="gap-3">
        <View className="flex-row items-start justify-between gap-3">
          <View className="flex-1">
            <Text className="text-foreground text-lg font-semibold">{instance.displayName}</Text>
            <Text className="text-muted text-sm mt-1">{instance.hostname}</Text>
          </View>
          <Chip color={presenceColor(instance.presence)} size="sm" variant="secondary">
            <Chip.Label>{instance.presence.toUpperCase()}</Chip.Label>
          </Chip>
        </View>
        <View className="flex-row items-center justify-between">
          <Text className="text-muted text-sm">{shared ? "Shared with me" : "Owned instance"}</Text>
          <Ionicons name="chevron-forward" size={18} color="#8a8a8a" />
        </View>
      </Pressable>
      {onRename ? (
        <View className="mt-3 gap-2">
          <TextField>
            <Input value={renameValue} onChangeText={setRenameValue} placeholder="Instance name" />
          </TextField>
          <Button onPress={() => onRename(renameValue.trim())} isDisabled={!canRename}>
            <Button.Label>Rename</Button.Label>
          </Button>
        </View>
      ) : null}
      {onRevoke ? (
        <Button className="mt-3" onPress={onRevoke}>
          <Button.Label>Revoke</Button.Label>
        </Button>
      ) : null}
    </Card>
  );
}

function EligibilityPanel({ result }: { result: ServerEligibilityResult | null }) {
  if (!result || result.status === "eligible") return null;
  const title = result.status === "oss_refused" ? "Native app unavailable" : "Server not eligible";
  const body =
    result.status === "oss_refused"
      ? "OSS self-hosted servers are designed for the web app as a PWA. The native app connects to hosted and licensed enterprise servers."
      : result.status === "enterprise_invalid"
        ? "This enterprise server does not have a valid native-app license. Use the web app or contact the server administrator."
        : result.message;
  return (
    <Surface variant="secondary" className="p-4 rounded-lg mb-4">
      <Text className="text-foreground font-semibold mb-1">{title}</Text>
      <Text className="text-muted text-sm">{body}</Text>
    </Surface>
  );
}

export default function InstancesHome() {
  const router = useRouter();
  const { toast } = useToast();
  const { data: session } = authClient.useSession();
  const [eligibility, setEligibility] = useState<ServerEligibilityResult | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const profile = useQuery(orpc.entitlements.deploymentProfile.queryOptions());
  const entitlements = useQuery({
    ...orpc.entitlements.mine.queryOptions(),
    enabled: !!session?.user,
  });
  const mine = useQuery({ ...orpc.instances.listMine.queryOptions(), enabled: !!session?.user });
  const pending = useQuery({
    ...orpc.instanceSharing.listPendingForMe.queryOptions(),
    enabled: !!session?.user,
  });
  const shared = useQuery({
    ...orpc.instanceSharing.listSharedWithMe.queryOptions(),
    enabled: !!session?.user,
  });
  const acceptInvite = useMutation(
    orpc.instanceSharing.accept.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.instanceSharing.key() });
        toast.show({ variant: "success", label: "Invitation accepted" });
      },
    }),
  );
  const declineInvite = useMutation(
    orpc.instanceSharing.decline.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.instanceSharing.key() });
        toast.show({ variant: "success", label: "Invitation declined" });
      },
    }),
  );
  const revoke = useMutation(
    orpc.instances.revoke.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.instances.key() });
        toast.show({ variant: "success", label: "Instance revoked" });
      },
    }),
  );
  const rename = useMutation(
    orpc.instances.rename.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.instances.key() });
        toast.show({ variant: "success", label: "Instance renamed" });
      },
    }),
  );

  useEffect(() => {
    verifyServerEligibility(env.EXPO_PUBLIC_SERVER_URL).then(setEligibility);
  }, []);

  useEffect(() => {
    if (!session?.user || entitlements.data?.nativeAppAccess !== true) return;
    registerNativePushToken().catch(() => undefined);
  }, [session?.user, entitlements.data?.nativeAppAccess]);

  const onRefresh = async () => {
    setRefreshing(true);
    try {
      await Promise.all([
        profile.refetch(),
        entitlements.refetch(),
        mine.refetch(),
        pending.refetch(),
        shared.refetch(),
      ]);
    } finally {
      setRefreshing(false);
    }
  };

  if (!session?.user) {
    return (
      <Container className="p-6">
        <View className="py-4 mb-6">
          <Text className="text-4xl font-bold text-foreground mb-2">Flycockpit</Text>
          <Text className="text-muted text-base">
            Sign in to control your cockpit-cli sessions.
          </Text>
        </View>
        <EligibilityPanel result={eligibility} />
        <Surface variant="secondary" className="p-4 rounded-lg">
          <Text className="text-foreground font-semibold mb-1">Account required</Text>
          <Text className="text-muted text-sm">
            Use the Account tab to sign in before opening remote sessions.
          </Text>
        </Surface>
      </Container>
    );
  }

  const eligibilityBlocked = eligibility !== null && eligibility.status !== "eligible";
  const nativeBlocked =
    eligibilityBlocked ||
    profile.data?.nativeAppEligible === false ||
    entitlements.data?.nativeAppAccess === false;

  return (
    <Container
      className="p-6"
      scrollViewProps={{
        refreshControl: <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />,
      }}
    >
      <View className="py-4 mb-4">
        <Text className="text-4xl font-bold text-foreground mb-2">Instances</Text>
        <Text className="text-muted text-base">
          Remote control for active cockpit-cli sessions.
        </Text>
      </View>

      <EligibilityPanel result={eligibility} />

      {nativeBlocked ? (
        <Surface variant="secondary" className="p-4 rounded-lg mb-5">
          <Text className="text-foreground font-semibold mb-1">
            {eligibilityBlocked
              ? "Use the web app for this server"
              : "Native access is not enabled"}
          </Text>
          <Text className="text-muted text-sm">
            {eligibilityBlocked
              ? "This server is not available in the native app. Open the server in a browser and install it as a PWA for remote control."
              : "Native remote control is available on hosted Pro plans and licensed enterprise servers."}
          </Text>
        </Surface>
      ) : null}

      {nativeBlocked ? null : (
        <>
          {pending.data?.invitations.length ? (
            <View className="gap-3 mb-5">
              <Text className="text-foreground text-xl font-semibold">Pending invitations</Text>
              {pending.data.invitations.map((invite) => (
                <Surface key={invite.id} variant="secondary" className="p-4 rounded-lg">
                  <Text className="text-foreground font-semibold">
                    {invite.instance.displayName}
                  </Text>
                  <Text className="text-muted text-sm mt-1">
                    {invite.scope.replaceAll("_", " ")}
                  </Text>
                  <View className="flex-row gap-3 mt-3">
                    <Button onPress={() => acceptInvite.mutate({ grantId: invite.id })}>
                      <Button.Label>Accept</Button.Label>
                    </Button>
                    <Button onPress={() => declineInvite.mutate({ grantId: invite.id })}>
                      <Button.Label>Decline</Button.Label>
                    </Button>
                  </View>
                </Surface>
              ))}
            </View>
          ) : null}

          <View className="gap-3 mb-5">
            <Text className="text-foreground text-xl font-semibold">My instances</Text>
            {mine.isPending ? <Spinner /> : null}
            {mine.data?.instances.length ? (
              mine.data.instances.map((instance) => (
                <InstanceCard
                  key={instance.id}
                  instance={instance}
                  onOpen={() =>
                    router.push({
                      pathname: "/instances/[instanceId]",
                      params: { instanceId: instance.id },
                    })
                  }
                  onRename={(displayName) =>
                    rename.mutate({ instanceId: instance.id, displayName })
                  }
                  onRevoke={() => revoke.mutate({ instanceId: instance.id })}
                />
              ))
            ) : !mine.isPending ? (
              <Surface variant="secondary" className="p-4 rounded-lg">
                <Text className="text-muted text-sm">
                  No cockpit-cli instances are connected yet.
                </Text>
              </Surface>
            ) : null}
          </View>

          <View className="gap-3">
            <Text className="text-foreground text-xl font-semibold">Shared with me</Text>
            {shared.data?.sharedInstances.length ? (
              shared.data.sharedInstances.map((entry) => (
                <InstanceCard
                  key={entry.instance.id}
                  instance={entry.instance}
                  shared
                  onOpen={() =>
                    router.push({
                      pathname: "/instances/[instanceId]",
                      params: { instanceId: entry.instance.id },
                    })
                  }
                />
              ))
            ) : (
              <Surface variant="secondary" className="p-4 rounded-lg">
                <Text className="text-muted text-sm">No shared instances are available.</Text>
              </Surface>
            )}
          </View>
        </>
      )}
    </Container>
  );
}
