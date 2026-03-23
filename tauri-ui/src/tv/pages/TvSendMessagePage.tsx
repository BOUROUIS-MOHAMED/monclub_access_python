import { useEffect, useRef, useState } from "react";
import { ImageIcon, Minus, Plus, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { post } from "@/api/client";
import { getTvHostBindings } from "@/tv/api/runtime";

async function closeWindow() {
  try {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    await getCurrentWindow().close();
  } catch {
    // no-op — only runs inside Tauri
  }
}

export default function TvSendMessagePage() {
  const params = new URLSearchParams(window.location.search);
  const bindingId = Number(params.get("bindingId") ?? 0);

  const [screenLabel, setScreenLabel] = useState(`Écran #${bindingId}`);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [counter, setCounter] = useState(5);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Resolve the screen label from the API
  useEffect(() => {
    if (!bindingId) return;
    getTvHostBindings()
      .then((res) => {
        const match = res.rows.find((b) => b.id === bindingId);
        if (match) {
          setScreenLabel(
            match.screen_label || match.monitor_label || `Écran #${bindingId}`,
          );
        }
      })
      .catch(() => {});
  }, [bindingId]);

  function handleImageChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setImagePreview(ev.target?.result as string);
    reader.readAsDataURL(file);
  }

  function handleClearImage() {
    setImagePreview(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  function handleCounterChange(delta: number) {
    setCounter((prev) => Math.min(10, Math.max(3, prev + delta)));
  }

  async function handleConfirm() {
    try {
      await post("/tv/screen-messages", {
        bindingId,
        title,
        description,
        imageBase64: imagePreview ?? null,
        displayDurationSec: counter,
      });
    } catch {
      // saved best-effort — still close
    }
    void closeWindow();
  }

  return (
    <div className="flex flex-col min-h-screen bg-background text-foreground p-5 gap-4">
      {/* Header */}
      <div>
        <h1 className="text-[15px] font-semibold">Envoyer un message</h1>
        <p className="text-[12px] text-muted-foreground mt-0.5">→ {screenLabel}</p>
      </div>

      {/* Title */}
      <div className="space-y-1.5">
        <Label htmlFor="msg-title" className="text-[13px]">Titre</Label>
        <Input
          id="msg-title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Titre du message"
          className="h-8 text-[13px]"
        />
      </div>

      {/* Description */}
      <div className="space-y-1.5">
        <Label htmlFor="msg-desc" className="text-[13px]">Description</Label>
        <textarea
          id="msg-desc"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Description du message…"
          rows={3}
          className="w-full resize-none rounded-md border border-input bg-background px-3 py-2 text-[13px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
        />
      </div>

      {/* Image */}
      <div className="space-y-1.5">
        <Label className="text-[13px]">Image</Label>
        {imagePreview ? (
          <div className="relative w-full overflow-hidden rounded-md border border-border">
            <img
              src={imagePreview}
              alt="Aperçu"
              className="max-h-32 w-full object-contain"
            />
            <button
              type="button"
              onClick={handleClearImage}
              className="absolute right-1.5 top-1.5 rounded-full bg-background/80 p-0.5 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="flex w-full items-center justify-center gap-2 rounded-md border border-dashed border-border py-4 text-[13px] text-muted-foreground hover:border-primary/50 hover:text-foreground transition-colors"
          >
            <ImageIcon className="h-4 w-4" />
            Choisir une image
          </button>
        )}
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={handleImageChange}
        />
      </div>

      {/* Counter */}
      <div className="space-y-1.5">
        <Label className="text-[13px]">Durée d'affichage (secondes)</Label>
        <div className="flex items-center gap-3">
          <Button
            type="button"
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={() => handleCounterChange(-1)}
            disabled={counter <= 3}
          >
            <Minus className="h-3.5 w-3.5" />
          </Button>
          <span className="w-8 text-center text-[15px] font-semibold tabular-nums">
            {counter}
          </span>
          <Button
            type="button"
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={() => handleCounterChange(1)}
            disabled={counter >= 10}
          >
            <Plus className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {/* Actions */}
      <div className="mt-auto pt-2">
        <Button size="sm" className="w-full" onClick={() => void handleConfirm()}>
          Confirmer
        </Button>
      </div>
    </div>
  );
}
