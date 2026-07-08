import { createFileRoute, Outlet } from "@tanstack/react-router";

export const Route = createFileRoute("/$lang/admin/videos")({
  component: AdminVideosLayout,
});

function AdminVideosLayout() {
  return <Outlet />;
}
