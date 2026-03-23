export async function setTvKeepBackgroundOnClose(enabled: boolean): Promise<void> {
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("set_keep_background_on_close", { enabled });
  } catch {
    // Browser/dev mode or unsupported host.
  }
}
