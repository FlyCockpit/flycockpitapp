import { createFileRoute, Outlet } from "@tanstack/react-router";

export const Route = createFileRoute("/$lang/admin/assets")({
  component: AdminAssetsLayout,
});

function AdminAssetsLayout() {
  return <Outlet />;
}
