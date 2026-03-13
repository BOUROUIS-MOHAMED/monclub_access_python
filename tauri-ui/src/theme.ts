import { createTheme } from "@mui/material/styles";

const theme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: "#1e90ff", light: "#63b8ff", dark: "#0066cc" },
    secondary: { main: "#ff6b35" },
    background: { default: "#0a0e14", paper: "#111820" },
    success: { main: "#2ecc71" },
    error: { main: "#e74c3c" },
    warning: { main: "#f39c12" },
    info: { main: "#3498db" },
    divider: "#1e2a3a",
    text: { primary: "#e6edf3", secondary: "#8b949e" },
  },
  typography: {
    fontFamily: '"Inter","Segoe UI","Roboto",sans-serif',
    h4: { fontWeight: 700 },
    h5: { fontWeight: 600 },
    h6: { fontWeight: 600 },
  },
  shape: { borderRadius: 10 },
  components: {
    MuiCard: { styleOverrides: { root: { backgroundImage: "none", border: "1px solid #1e2a3a" } } },
    MuiDrawer: { styleOverrides: { paper: { backgroundColor: "#0d1117", borderRight: "1px solid #1e2a3a" } } },
    MuiAppBar: { styleOverrides: { root: { backgroundColor: "#0d1117", borderBottom: "1px solid #1e2a3a", backgroundImage: "none" } } },
    MuiButton: { defaultProps: { disableElevation: true }, styleOverrides: { root: { textTransform: "none", fontWeight: 600 } } },
    MuiChip: { styleOverrides: { root: { fontWeight: 600 } } },
  },
});

export default theme;

