import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { installTrustedTypes } from "@/security/trustedTypes";
import { App } from "@/app/App";
import "./index.css";

// Install the Trusted Types policy before any rendering occurs.
installTrustedTypes();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
