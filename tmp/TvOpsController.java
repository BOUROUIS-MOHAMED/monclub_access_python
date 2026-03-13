package com.tpjava.tpjava.Controllers;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tpjava.tpjava.AppConstants;
import com.tpjava.tpjava.Configuration.JwtService;
import com.tpjava.tpjava.Helper.Utils;
import com.tpjava.tpjava.Models.*;
import com.tpjava.tpjava.Repositories.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.*;

@RestController
@RequiredArgsConstructor
@RequestMapping(AppConstants.API_BASE_URL)
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class TvOpsController {

    private final JwtService jwtService;
    private final MainAccountRepository mainAccountRepository;
    private final TvService tvService;
    private final ObjectMapper objectMapper;

    private final TvScreenRepository tvScreenRepository;
    private final TvScreenHeartbeatRepository tvScreenHeartbeatRepository;
    private final TvRuntimeEventRepository tvRuntimeEventRepository;
    private final TvProofEventRepository tvProofEventRepository;
    private final TvResolvedSnapshotRepository tvResolvedSnapshotRepository;
    private final TvAdSlotRepository tvAdSlotRepository;

    private MainAccountModel account(HttpServletRequest request) {
        return Utils.resolveAccount(request, jwtService, mainAccountRepository);
    }

    private GymModel gym(HttpServletRequest request, Long gymId) {
        return tvService.resolveGymScope(account(request), gymId);
    }

    @GetMapping("/manager/tv/overview")
    public Map<String, Object> overview(HttpServletRequest request, @RequestParam(required = false) Long gymId) {
        GymModel g = gym(request, gymId);
        List<TvScreen> screens = tvScreenRepository.findAllByGymIdOrderByUpdatedAtDesc(g.getId());
        Map<Long, TvScreenHeartbeat> latestHb = new HashMap<>();
        for (TvScreenHeartbeat hb : tvScreenHeartbeatRepository.findTop200ByGymIdOrderByReceivedAtDesc(g.getId())) {
            latestHb.putIfAbsent(hb.getScreenId(), hb);
        }

        int online = 0;
        for (TvScreen s : screens) {
            TvScreenHeartbeat hb = latestHb.get(s.getId());
            if (hb != null && Boolean.TRUE.equals(hb.getOnline())) online++;
        }

        List<Map<String, Object>> campaigns = campaignsInternal(g.getId());

        long used = 0L;
        long quota = 0L;
        long fallback = tvRuntimeEventRepository.findTop500ByGymIdOrderByReceivedAtDesc(g.getId()).stream()
                .filter(e -> safe(e.getEventCode()).toUpperCase(Locale.ROOT).contains("FALLBACK"))
                .count();

        return Map.of(
                "ok", true,
                "gymId", g.getId(),
                "totalScreens", screens.size(),
                "onlineScreens", online,
                "offlineScreens", Math.max(0, screens.size() - online),
                "activeCampaigns", campaigns.stream().filter(c -> "ACTIVE".equals(c.get("status"))).count(),
                "proofEvents", tvProofEventRepository.countByGymId(g.getId()),
                "runtimeEvents", tvRuntimeEventRepository.countByGymId(g.getId()),
                "fallbackEvents", fallback,
                "usedStorageBytes", used,
                "storageQuotaBytes", quota,
                "campaigns", campaigns.stream().limit(8).toList()
        );
    }

    @GetMapping("/manager/tv/health")
    public Map<String, Object> health(HttpServletRequest request, @RequestParam(required = false) Long gymId) {
        GymModel g = gym(request, gymId);
        List<TvScreen> screens = tvScreenRepository.findAllByGymIdOrderByUpdatedAtDesc(g.getId());
        List<TvRuntimeEvent> incidents = tvRuntimeEventRepository.findTop500ByGymIdOrderByReceivedAtDesc(g.getId());

        List<Map<String, Object>> screenRows = new ArrayList<>();
        for (TvScreen s : screens) {
            TvScreenHeartbeat hb = tvScreenHeartbeatRepository.findTopByScreenIdOrderByReceivedAtDesc(s.getId()).orElse(null);
            long runtimeCount = tvRuntimeEventRepository.countByGymIdAndScreenId(g.getId(), s.getId());
            long proofCount = tvProofEventRepository.countByGymIdAndScreenId(g.getId(), s.getId());
            long fallbackCount = incidents.stream().filter(ev -> Objects.equals(ev.getScreenId(), s.getId()))
                    .filter(ev -> safe(ev.getEventCode()).toUpperCase(Locale.ROOT).contains("FALLBACK"))
                    .count();
            screenRows.add(Map.of(
                    "screenId", s.getId(),
                    "screenName", safe(s.getName()),
                    "online", hb != null && Boolean.TRUE.equals(hb.getOnline()),
                    "playerHealthState", hb == null ? null : hb.getPlayerHealthState(),
                    "lastHeartbeatAt", s.getLastHeartbeatAt(),
                    "activeSnapshotVersion", s.getActiveSnapshotVersion(),
                    "runtimeEvents", runtimeCount,
                    "fallbackEvents", fallbackCount,
                    "proofEvents", proofCount
            ));
        }

        Map<Long, String> screenNames = screens.stream().collect(Collectors.toMap(TvScreen::getId, TvScreen::getName));
        List<Map<String, Object>> incidentRows = incidents.stream().limit(200)
                .map(ev -> Map.of(
                        "eventId", safe(ev.getRuntimeEventId()),
                        "screenId", ev.getScreenId(),
                        "screenName", safe(screenNames.get(ev.getScreenId())),
                        "severity", safe(ev.getSeverity()),
                        "eventCode", safe(ev.getEventCode()),
                        "message", safe(ev.getMessage()),
                        "receivedAt", ev.getReceivedAt()
                ))
                .toList();

        return Map.of("ok", true, "screens", screenRows, "incidents", incidentRows);
    }
    @GetMapping("/manager/tv/screens/{screenId}/details")
    public Map<String, Object> screenDetails(
            HttpServletRequest request,
            @PathVariable Long screenId,
            @RequestParam(required = false) Long gymId
    ) {
        GymModel g = gym(request, gymId);
        TvScreen screen = tvScreenRepository.findByIdAndGymId(screenId, g.getId())
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "TV screen not found"));

        TvScreenHeartbeat hb = tvScreenHeartbeatRepository.findTopByScreenIdOrderByReceivedAtDesc(screen.getId()).orElse(null);
        List<TvResolvedSnapshot> snapshots = tvResolvedSnapshotRepository.findAllByScreenIdOrderByGeneratedAtDesc(screen.getId());
        List<TvRuntimeEvent> runtime = tvRuntimeEventRepository.findTop200ByGymIdAndScreenIdOrderByReceivedAtDesc(g.getId(), screen.getId());
        List<TvProofEvent> proof = tvProofEventRepository.findTop500ByGymIdAndScreenIdOrderByLastReceivedAtDesc(g.getId(), screen.getId());

        List<Map<String, Object>> runtimeRows = runtime.stream().limit(100).map(r -> Map.of(
                "runtimeEventId", safe(r.getRuntimeEventId()),
                "severity", safe(r.getSeverity()),
                "eventCode", safe(r.getEventCode()),
                "message", safe(r.getMessage()),
                "details", readMap(r.getDetailsJson()),
                "receivedAt", r.getReceivedAt()
        )).toList();

        List<Map<String, Object>> proofRows = proof.stream().limit(100).map(p -> Map.of(
                "proofEventId", safe(p.getProofEventId()),
                "adSlotId", p.getAdSlotId(),
                "contentType", safe(p.getContentType()),
                "resultStatus", p.getResultStatus() == null ? null : p.getResultStatus().name(),
                "completionRate", p.getCompletionRate(),
                "interruptionReason", safe(p.getInterruptionReason()),
                "lastReceivedAt", p.getLastReceivedAt(),
                "ingestCount", p.getIngestCount()
        )).toList();

        List<Map<String, Object>> snapshotRows = snapshots.stream().limit(30).map(s -> Map.of(
                "id", s.getId(),
                "version", safe(s.getVersion()),
                "active", s.isActive(),
                "generatedAt", s.getGeneratedAt(),
                "playbackPolicyVersion", safe(s.getPlaybackPolicyVersion())
        )).toList();

        return Map.of(
                "ok", true,
                "screen", screen,
                "monitor", Map.of(
                        "online", hb != null && Boolean.TRUE.equals(hb.getOnline()),
                        "playerHealthState", hb == null ? null : hb.getPlayerHealthState(),
                        "lastHeartbeatAt", screen.getLastHeartbeatAt(),
                        "lastSnapshotVersion", screen.getActiveSnapshotVersion(),
                        "proofCount", proof.size(),
                        "runtimeEventCount", runtime.size()
                ),
                "snapshots", snapshotRows,
                "runtimeEvents", runtimeRows,
                "proofEvents", proofRows,
                "fallbackActivations", runtime.stream().filter(e -> safe(e.getEventCode()).toUpperCase(Locale.ROOT).contains("FALLBACK")).count()
        );
    }

    @GetMapping("/manager/tv/campaigns")
    public Map<String, Object> campaigns(HttpServletRequest request, @RequestParam(required = false) Long gymId) {
        GymModel g = gym(request, gymId);
        return Map.of("ok", true, "rows", campaignsInternal(g.getId()));
    }

    @GetMapping("/manager/tv/campaigns/{campaignRef}")
    public Map<String, Object> campaignDetails(
            HttpServletRequest request,
            @PathVariable String campaignRef,
            @RequestParam(required = false) Long gymId
    ) {
        GymModel g = gym(request, gymId);
        String target = safe(campaignRef);
        List<TvAdSlot> slots = tvAdSlotRepository.findAllByScreenGymIdOrderBySlotDateAscStartTimeAsc(g.getId()).stream()
                .filter(s -> target.equalsIgnoreCase(safe(s.getCampaignRef())))
                .toList();
        if (slots.isEmpty()) throw new ResponseStatusException(NOT_FOUND, "Campaign not found");

        Set<Long> slotIds = slots.stream().map(TvAdSlot::getId).collect(Collectors.toSet());
        List<TvProofEvent> proof = tvProofEventRepository.findTop500ByGymIdOrderByLastReceivedAtDesc(g.getId()).stream()
                .filter(p -> p.getAdSlotId() != null && slotIds.contains(p.getAdSlotId()))
                .toList();

        return Map.of(
                "ok", true,
                "campaignRef", target,
                "slots", slots,
                "proof", proof,
                "deliveredProofCount", proof.size(),
                "slotCount", slots.size()
        );
    }

    @GetMapping("/manager/tv/stats/proof")
    public Map<String, Object> proofStats(HttpServletRequest request, @RequestParam(required = false) Long gymId) {
        GymModel g = gym(request, gymId);
        List<TvProofEvent> latest = tvProofEventRepository.findTop500ByGymIdOrderByLastReceivedAtDesc(g.getId());
        long replay = latest.stream().filter(e -> e.getIngestCount() != null && e.getIngestCount() > 1).count();
        long acceptedNew = latest.size() - replay;
        Map<String, Long> reasons = latest.stream()
                .map(TvProofEvent::getInterruptionReason)
                .filter(r -> r != null && !r.isBlank())
                .collect(Collectors.groupingBy(String::trim, Collectors.counting()));

        return Map.of(
                "ok", true,
                "total", tvProofEventRepository.countByGymId(g.getId()),
                "acceptedNew", acceptedNew,
                "acceptedReplay", replay,
                "rejectedInvalid", 0,
                "underDeliveryReasons", reasons,
                "latestEvents", latest.stream().limit(100).toList()
        );
    }

    private List<Map<String, Object>> campaignsInternal(Long gymId) {
        List<TvAdSlot> slots = tvAdSlotRepository.findAllByScreenGymIdOrderBySlotDateAscStartTimeAsc(gymId).stream()
                .filter(s -> !safe(s.getCampaignRef()).isBlank())
                .toList();
        if (slots.isEmpty()) return List.of();

        Map<String, List<TvAdSlot>> grouped = slots.stream().collect(Collectors.groupingBy(s -> safe(s.getCampaignRef())));
        List<TvProofEvent> proof = tvProofEventRepository.findTop500ByGymIdOrderByLastReceivedAtDesc(gymId);
        LocalDate today = LocalDate.now(ZoneOffset.UTC);

        List<Map<String, Object>> out = new ArrayList<>();
        for (Map.Entry<String, List<TvAdSlot>> e : grouped.entrySet()) {
            Set<Long> slotIds = e.getValue().stream().map(TvAdSlot::getId).collect(Collectors.toSet());
            long delivered = proof.stream().filter(p -> p.getAdSlotId() != null && slotIds.contains(p.getAdSlotId())).count();
            int slotCount = e.getValue().size();
            int duration = e.getValue().stream().map(TvAdSlot::getDurationSec).filter(Objects::nonNull).reduce(0, Integer::sum);
            LocalDate firstDate = e.getValue().stream().map(TvAdSlot::getSlotDate).filter(Objects::nonNull).min(LocalDate::compareTo).orElse(null);
            LocalDate lastDate = e.getValue().stream().map(TvAdSlot::getSlotDate).filter(Objects::nonNull).max(LocalDate::compareTo).orElse(null);
            String status = (lastDate != null && lastDate.isBefore(today)) ? (delivered >= slotCount ? "COMPLETED" : "UNDER_DELIVERED") : "ACTIVE";

            out.add(Map.of(
                    "campaignRef", e.getKey(),
                    "slotCount", slotCount,
                    "scheduledDurationSec", duration,
                    "deliveredProofCount", delivered,
                    "firstDate", firstDate,
                    "lastDate", lastDate,
                    "status", status
            ));
        }

        out.sort((a, b) -> String.valueOf(b.get("lastDate")).compareTo(String.valueOf(a.get("lastDate"))));
        return out;
    }

    private String safe(String s) {
        return s == null ? "" : s.trim();
    }

    private Map<String, Object> readMap(String json) {
        if (json == null || json.isBlank()) return new LinkedHashMap<>();
        try {
            return objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }
}
