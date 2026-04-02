import React, { createContext, useContext, useState, useEffect, useRef } from "react";
import { openSSE } from "@/api/client";

export interface EnrollMeta {
  userId: string;
  fullName: string;
  fingerId: number;
}

interface EnrollmentState {
  enrollMeta: EnrollMeta | null;
  clearMeta: () => void;
}

const EnrollmentContext = createContext<EnrollmentState>({
  enrollMeta: null,
  clearMeta: () => {},
});

export function EnrollmentProvider({ children }: { children: React.ReactNode }) {
  const [enrollMeta, setEnrollMeta] = useState<EnrollMeta | null>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const es = openSSE("/enroll/events", (type, data) => {
      if (type === "enroll_started") {
        setEnrollMeta({
          userId: String(data?.userId ?? ""),
          fullName: String(data?.fullName ?? ""),
          fingerId: Number(data?.fingerId ?? 0),
        });
      }
    });
    esRef.current = es;
    return () => {
      es.close();
      esRef.current = null;
    };
  }, []);

  const clearMeta = () => setEnrollMeta(null);

  return (
    <EnrollmentContext.Provider value={{ enrollMeta, clearMeta }}>
      {children}
    </EnrollmentContext.Provider>
  );
}

export function useEnrollment() {
  return useContext(EnrollmentContext);
}
