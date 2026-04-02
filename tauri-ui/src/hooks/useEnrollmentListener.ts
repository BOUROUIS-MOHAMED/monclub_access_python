import { useEffect, useRef } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useEnrollment, EnrollMeta } from "@/context/EnrollmentContext";

/**
 * Watches for remote enroll_started events and navigates to /enroll.
 * Safe to call multiple times — the locationRef guard prevents loops.
 */
export function useEnrollmentListener() {
  const { enrollMeta } = useEnrollment();
  const navigate = useNavigate();
  const location = useLocation();

  const locationRef = useRef(location);
  useEffect(() => {
    locationRef.current = location;
  }, [location]);

  const prevMetaRef = useRef<EnrollMeta | null>(null);

  useEffect(() => {
    if (enrollMeta && enrollMeta !== prevMetaRef.current) {
      prevMetaRef.current = enrollMeta;
      void invoke("focus_and_show_enrollment").catch(() => {});
      if (!locationRef.current.pathname.startsWith("/enroll")) {
        navigate("/enroll");
      }
    }
    if (!enrollMeta) {
      prevMetaRef.current = null;
    }
  }, [enrollMeta, navigate]);
}
