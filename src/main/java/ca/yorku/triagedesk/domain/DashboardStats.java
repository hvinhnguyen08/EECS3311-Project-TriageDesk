package ca.yorku.triagedesk.domain;

import java.util.Map;

/** Totals shown on the dashboard. The maps keep the insertion order they were built in (largest first). */
public record DashboardStats(
        int totalEvents,
        Map<String, Integer> topSourceIps,
        Map<String, Integer> topUsers,
        Map<String, Integer> casesByState) {

    public DashboardStats {
        topSourceIps = topSourceIps == null ? Map.of() : topSourceIps;
        topUsers = topUsers == null ? Map.of() : topUsers;
        casesByState = casesByState == null ? Map.of() : casesByState;
    }

    /** True when nothing has been imported and there are no cases (the state counts may all be zero). */
    public boolean isEmpty() {
        return totalEvents == 0 && casesByState.values().stream().allMatch(n -> n == null || n == 0);
    }
}
