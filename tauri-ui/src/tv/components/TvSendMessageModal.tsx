import { useRef, useState } from "react";
import { ImageIcon, Minus, Plus, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface TvSendMessageModalProps {
  screenLabel: string;
  onClose: () => void;
}

export function TvSendMessageModal({ screenLabel, onClose }: TvSendMessageModalProps) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [counter, setCounter] = useState(5);
  const fileInputRef = useRef<HTMLInputElement>(null);

  function handleImageChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setImageFile(file);
    const reader = new FileReader();
    reader.onload = (ev) => setImagePreview(ev.target?.result as string);
    reader.readAsDataURL(file);
  }

  function handleClearImage() {
    setImageFile(null);
    setImagePreview(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  function handleCounterChange(delta: number) {
    setCounter((prev) => Math.min(10, Math.max(3, prev + delta)));
  }

  function handleConfirm() {
    // Data available: title, description, imageFile, counter
    onClose();
  }

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">
            Envoyer un message
            <span className="ml-2 text-[12px] font-normal text-muted-foreground">
              → {screenLabel}
            </span>
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-1">
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
                  className="max-h-36 w-full object-contain"
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
                className="flex w-full items-center justify-center gap-2 rounded-md border border-dashed border-border py-5 text-[13px] text-muted-foreground hover:border-primary/50 hover:text-foreground transition-colors"
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
        </div>

        <DialogFooter>
          <Button variant="outline" size="sm" onClick={onClose}>
            Annuler
          </Button>
          <Button size="sm" onClick={handleConfirm}>
            Confirmer
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
