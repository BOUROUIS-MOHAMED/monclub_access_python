import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import TvApp from "@/tv/TvApp";
import { installSemanticTokenStyles } from "./theme/colors";
import { getDesktopRuntimeContext, loadDesktopRuntimeContext } from "./runtime/desktopContext";
import "./index.css";

installSemanticTokenStyles();

const root = ReactDOM.createRoot(document.getElementById("root")!);

async function bootstrap() {
  await loadDesktopRuntimeContext();
  const runtimeContext = getDesktopRuntimeContext();
  const ShellApp = runtimeContext.role === "tv" ? TvApp : App;

  root.render(
    <React.StrictMode>
      <ShellApp />
    </React.StrictMode>,
  );
}

void bootstrap();
