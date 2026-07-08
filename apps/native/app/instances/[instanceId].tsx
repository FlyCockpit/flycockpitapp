import type { ProjectSummary } from "@flycockpit/cockpit-protocol";
import { useLocalSearchParams, useRouter } from "expo-router";
import { Button, Card, Chip, Spinner, Surface } from "heroui-native";
import { useEffect, useState } from "react";
import { Pressable, Text, View } from "react-native";

import { Container } from "@/components/container";
import { useNativeRemoteClient } from "@/hooks/use-native-remote-client";

function projectLabel(project: ProjectSummary) {
  return (
    project.displayName ||
    project.projectRoot.split("/").filter(Boolean).at(-1) ||
    project.projectRoot
  );
}

export default function InstanceProjects() {
  const router = useRouter();
  const params = useLocalSearchParams<{ instanceId?: string }>();
  const instanceId = Array.isArray(params.instanceId) ? params.instanceId[0] : params.instanceId;
  const { client, status, statusDetail, tokenQuery } = useNativeRemoteClient(instanceId);
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [isLoadingProjects, setIsLoadingProjects] = useState(false);

  const loadProjects = async () => {
    if (!client) return;
    setIsLoadingProjects(true);
    setLoadError(null);
    try {
      const result = await client.listProjects();
      setProjects(result.projects);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Could not load projects.");
    } finally {
      setIsLoadingProjects(false);
    }
  };

  useEffect(() => {
    if (status === "connected" && projects.length === 0) {
      loadProjects();
    }
  }, [status, projects.length]);

  return (
    <Container className="p-6">
      <View className="py-4 mb-4">
        <Text className="text-4xl font-bold text-foreground mb-2">Projects</Text>
        <Text className="text-muted text-base">
          Open a project to review sessions and approvals.
        </Text>
      </View>

      <Surface variant="secondary" className="p-4 rounded-lg mb-5">
        <View className="flex-row items-center justify-between gap-3">
          <View className="flex-1">
            <Text className="text-foreground font-semibold">Relay connection</Text>
            <Text className="text-muted text-sm mt-1">
              {statusDetail ?? tokenQuery.error?.message ?? "Session transport"}
            </Text>
          </View>
          <Chip
            variant="secondary"
            color={status === "connected" ? "success" : status === "error" ? "danger" : "default"}
          >
            <Chip.Label>{status.toUpperCase()}</Chip.Label>
          </Chip>
        </View>
      </Surface>

      {tokenQuery.isPending ? <Spinner /> : null}
      {tokenQuery.isError ? (
        <Surface variant="secondary" className="p-4 rounded-lg">
          <Text className="text-foreground font-semibold mb-1">Cannot open this instance</Text>
          <Text className="text-muted text-sm">{tokenQuery.error.message}</Text>
        </Surface>
      ) : null}

      <View className="gap-3">
        <View className="flex-row items-center justify-between">
          <Text className="text-foreground text-xl font-semibold">Project list</Text>
          <Button onPress={loadProjects} isDisabled={!client || isLoadingProjects}>
            <Button.Label>{isLoadingProjects ? "Loading" : "Refresh"}</Button.Label>
          </Button>
        </View>
        {loadError ? <Text className="text-danger text-sm">{loadError}</Text> : null}
        {projects.map((project) => (
          <Card key={project.projectId} variant="secondary" className="p-4">
            <Pressable
              className="gap-2"
              onPress={() =>
                router.push({
                  pathname: "/instances/[instanceId]/projects/[projectId]",
                  params: {
                    instanceId: instanceId ?? "",
                    projectId: encodeURIComponent(project.projectId),
                    projectRoot: project.projectRoot,
                    name: projectLabel(project),
                  },
                })
              }
            >
              <View className="flex-row items-start justify-between gap-3">
                <View className="flex-1">
                  <Text className="text-foreground text-lg font-semibold">
                    {projectLabel(project)}
                  </Text>
                  <Text className="text-muted text-xs mt-1">{project.projectRoot}</Text>
                </View>
                {project.attentionCount > 0 ? (
                  <Chip color="warning" variant="secondary" size="sm">
                    <Chip.Label>{project.attentionCount} needs attention</Chip.Label>
                  </Chip>
                ) : null}
              </View>
              <Text className="text-muted text-sm">{project.sessionCount} sessions</Text>
            </Pressable>
          </Card>
        ))}
        {!projects.length && !isLoadingProjects && status === "connected" ? (
          <Surface variant="secondary" className="p-4 rounded-lg">
            <Text className="text-muted text-sm">No projects reported by this instance yet.</Text>
          </Surface>
        ) : null}
      </View>
    </Container>
  );
}
