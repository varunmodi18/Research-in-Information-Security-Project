// Pages added after the M3 skeleton register here.
import type { ReactNode } from "react";
import type { Role } from "./api/types";
import { AdminPage } from "./pages/AdminPage";
import { DevicePage } from "./pages/DevicePage";
import { EvaluationPage } from "./pages/EvaluationPage";
import { FramesPage } from "./pages/FramesPage";
import { LabPage } from "./pages/LabPage";
import { ReadingsPage } from "./pages/ReadingsPage";
import { TimelinePage } from "./pages/TimelinePage";

export const EXTRA_ROUTES: { path: string; min: Role; element: ReactNode }[] = [
  { path: "/networks/:id/devices/:dev", min: "viewer", element: <DevicePage /> },
  { path: "/networks/:id/timeline", min: "viewer", element: <TimelinePage /> },
  { path: "/networks/:id/frames", min: "viewer", element: <FramesPage /> },
  { path: "/networks/:id/readings", min: "operator", element: <ReadingsPage /> },
  { path: "/admin", min: "admin", element: <AdminPage /> },
  { path: "/lab", min: "operator", element: <LabPage /> },
  { path: "/evaluation", min: "viewer", element: <EvaluationPage /> },
];
