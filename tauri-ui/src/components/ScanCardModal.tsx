import { useEffect, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { CreditCard, Check, Copy, X, AlertCircle, Loader2 } from "lucide-react";
import { useScanCard } from "@/hooks/useScanCard";

interface Props {
  open: boolean;
  onClose: (cardNumber?: string) => void;
}

export default function ScanCardModal({ open, onClose }: Props) {
  const { status, startScan, stopScan } = useScanCard();
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (open) {
      startScan();
      return () => {
        stopScan();
      };
    }
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleCopy = async () => {
    if (status.lastResult?.cardNumber) {
      await navigator.clipboard.writeText(status.lastResult.cardNumber);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleClose = () => {
    stopScan();
    onClose(status.lastResult?.cardNumber);
  };

  const isConnecting = status.state === "connecting";
  const isScanning = status.state === "scanning";
  const hasResult = status.lastResult !== null;
  const hasError = status.state === "error";
  const sourceLabel =
    status.lastResult?.source === "zkemkeeper"
      ? "SCR100 (ZKEMKeeper)"
      : status.lastResult?.source === "network"
        ? "SCR100 (réseau)"
        : "USB";

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <CreditCard className="h-5 w-5" />
            Scanner une carte
          </DialogTitle>
        </DialogHeader>

        <div className="flex flex-col items-center py-8 gap-4">
          {isConnecting && (
            <>
              <Loader2 className="h-12 w-12 text-primary animate-spin" />
              <p className="text-sm text-muted-foreground">Connexion au lecteur...</p>
            </>
          )}

          {isScanning && !hasResult && (
            <>
              <div className="relative flex items-center justify-center">
                <CreditCard className="h-16 w-16 text-primary animate-pulse" />
              </div>
              <p className="text-sm text-muted-foreground">
                Passez la carte devant le lecteur...
              </p>
            </>
          )}

          {hasResult && (
            <>
              <div className="flex items-center gap-2 text-green-500">
                <Check className="h-6 w-6" />
                <span className="text-sm font-medium">Carte détectée !</span>
              </div>
              <div className="flex items-center gap-2 bg-muted rounded-lg px-4 py-3">
                <code className="text-2xl font-mono font-bold tracking-wider">
                  {status.lastResult!.cardNumber}
                </code>
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-8 w-8 shrink-0"
                  onClick={handleCopy}
                  title="Copier le numéro"
                >
                  {copied ? (
                    <Check className="h-4 w-4 text-green-500" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Source: {sourceLabel}
              </p>
            </>
          )}

          {hasError && (
            <>
              <AlertCircle className="h-12 w-12 text-destructive" />
              <p className="text-sm text-destructive text-center max-w-xs">
                {status.error}
              </p>
            </>
          )}
        </div>

        <DialogFooter>
          {hasResult ? (
            <Button variant="default" onClick={handleClose}>
              Fermer
            </Button>
          ) : (
            <Button variant="outline" onClick={handleClose}>
              <X className="h-4 w-4 mr-1" />
              Annuler
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
