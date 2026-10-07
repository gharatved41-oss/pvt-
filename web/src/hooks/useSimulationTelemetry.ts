'use client';

import { useState, useEffect } from 'react';
import { 
  collection, 
  query, 
  orderBy, 
  onSnapshot, 
  DocumentData, 
  QuerySnapshot 
} from 'firebase/firestore';
import { db } from '@/lib/firebase';
import { SimulationEvent } from '@/types';

export interface UseSimulationTelemetryResult {
  events: SimulationEvent[];
  latestEvent: SimulationEvent | null;
  loading: boolean;
  error: string | null;
}

/**
 * useSimulationTelemetry
 * Subscribes to real-time events streamed by the Autonomous Attack Path Engine
 * to /simulations/{simId}/events. Allows zero-polling live console updates.
 */
export function useSimulationTelemetry(simId: string | null): UseSimulationTelemetryResult {
  const [events, setEvents] = useState<SimulationEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(Boolean(simId));
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!simId) {
      setEvents([]);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    const eventsRef = collection(db, 'simulations', simId, 'events');
    const eventsQuery = query(eventsRef, orderBy('timestamp', 'asc'));

    const unsubscribe = onSnapshot(
      eventsQuery,
      (snapshot: QuerySnapshot<DocumentData>) => {
        const loadedEvents: SimulationEvent[] = [];
        snapshot.forEach((doc) => {
          loadedEvents.push({
            id: doc.id,
            ...(doc.data() as Omit<SimulationEvent, 'id'>),
          });
        });
        setEvents(loadedEvents);
        setLoading(false);
      },
      (err) => {
        console.error(`[Telemetry Error] Failed to stream events for sim ${simId}:`, err);
        setError(err.message);
        setLoading(false);
      }
    );

    return () => unsubscribe();
  }, [simId]);

  return {
    events,
    latestEvent: events.length > 0 ? events[events.length - 1] : null,
    loading,
    error,
  };
}
