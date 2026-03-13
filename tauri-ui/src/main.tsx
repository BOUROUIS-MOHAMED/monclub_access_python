import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { installSemanticTokenStyles } from "./theme/colors";
import "./index.css";

installSemanticTokenStyles();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
