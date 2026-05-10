package main;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe store for API traffic entries.
 */
public class ApiTrafficModel {
    
    public interface Listener {
        void onEntryAdded(ApiTrafficEntry entry);
        void onCleared();
    }
    
    private final List<ApiTrafficEntry> entries = new CopyOnWriteArrayList<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    private int nextId = 1;
    
    public void addEntry(ApiTrafficEntry entry) {
        entries.add(entry);
        for (Listener l : listeners) {
            l.onEntryAdded(entry);
        }
    }
    
    public void clear() {
        entries.clear();
        nextId = 1;
        for (Listener l : listeners) {
            l.onCleared();
        }
    }
    
    public List<ApiTrafficEntry> getEntries() {
        return Collections.unmodifiableList(entries);
    }
    
    public void addListener(Listener l) { listeners.add(l); }
    public void removeListener(Listener l) { listeners.remove(l); }
    public int getNextId() { return nextId++; }
}