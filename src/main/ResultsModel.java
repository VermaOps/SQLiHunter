package main;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe store for scan findings. Fires listeners when findings are added.
 */
public class ResultsModel {

    public interface Listener {
        void onFindingAdded(ScanFinding finding);
        void onCleared();
        void onFilterChanged();
    }

    private final List<ScanFinding> findings = new CopyOnWriteArrayList<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    private int totalScanned = 0;
    private int totalRequests = 0;
    private Integer currentFilterTrafficId = null;

    public void addFinding(ScanFinding finding) {
        findings.add(finding);
        for (Listener l : listeners) l.onFindingAdded(finding);
    }

    public void clear() {
        findings.clear();
        totalScanned = 0;
        totalRequests = 0;
        for (Listener l : listeners) l.onCleared();
    }

    public List<ScanFinding> getFindings() {
        return Collections.unmodifiableList(findings);
    }

    public List<ScanFinding> getFilteredFindings() {
        if (currentFilterTrafficId == null) {
            return Collections.unmodifiableList(findings);
        }
        return findings.stream()
                .filter(f -> f.getTrafficEntryId() == currentFilterTrafficId)
                .collect(java.util.stream.Collectors.toList());
    }

    public void setFilter(int trafficEntryId) {
        this.currentFilterTrafficId = trafficEntryId;
        for (Listener l : listeners) {
            l.onFilterChanged();
        }
    }

    public void clearFilter() {
        this.currentFilterTrafficId = null;
        for (Listener l : listeners) {
            l.onFilterChanged();
        }
    }

    public Integer getCurrentFilter() {
        return currentFilterTrafficId;
    }

    public void addListener(Listener l) { listeners.add(l); }
    public void removeListener(Listener l) { listeners.remove(l); }

    public void incrementScanned() { totalScanned++; }
    public void incrementRequests(int n) { totalRequests += n; }
    public int getTotalScanned() { return totalScanned; }
    public int getTotalRequests() { return totalRequests; }
    public int getFindingCount() { return findings.size(); }
}
