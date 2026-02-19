import React, { useCallback, useRef, useState, useEffect } from 'react';
import {
  View, ScrollView, StyleSheet, StatusBar,
  Dimensions, NativeSyntheticEvent, NativeScrollEvent,
  Text, SafeAreaView, TouchableOpacity, BackHandler,
} from 'react-native';
import { useSecureChapter } from '../hooks/useSecureChapter';
import { SecureImageViewer } from '../components/SecureImageViewer';
import { SecurityOrchestrator } from '../core/SecurityOrchestrator';

const { width: SW, height: SH } = Dimensions.get('window');

interface Params {
  chapterId: string;
  title?:    string;
}

/**
 * ChapterScreen — the main secure reading interface.
 *
 * Scroll strategy:
 *   - Load current page + one ahead
 *   - Release pages 2+ behind the viewport
 *   - Track scroll velocity for EphemeralKey entropy
 */
export const ChapterScreen: React.FC<{ route: { params: Params }; navigation: any }> = ({
  route, navigation
}) => {
  const { chapterId } = route.params;
  const {
    images, metadata, isReady,
    loadPage, releasePage, setScrollVelocity,
  } = useSecureChapter(chapterId);

  const [currentPage, setCurrentPage] = useState(0);
  const lastY      = useRef(0);
  const lastT      = useRef(Date.now());

  // Periodic security check while chapter is open
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        await SecurityOrchestrator.periodicCheck();
      } catch {
        // Violation handled inside periodicCheck → process crash
      }
    }, 15_000);
    return () => clearInterval(interval);
  }, []);

  // Load first pages on ready
  useEffect(() => {
    if (isReady && metadata && metadata.totalImages > 0) {
      loadPage(0);
      if (metadata.totalImages > 1) loadPage(1);
    }
  }, [isReady, metadata]);

  // Hardware back button
  useEffect(() => {
    const sub = BackHandler.addEventListener('hardwareBackPress', () => {
      navigation.goBack();
      return true;
    });
    return () => sub.remove();
  }, [navigation]);

  const handleScroll = useCallback((e: NativeSyntheticEvent<NativeScrollEvent>) => {
    const now = Date.now();
    const y   = e.nativeEvent.contentOffset.y;
    const dt  = Math.max(1, now - lastT.current);

    setScrollVelocity(Math.abs(y - lastY.current) / dt);
    lastY.current = y;
    lastT.current = now;

    const page = Math.round(y / SH);
    if (page !== currentPage) {
      setCurrentPage(page);

      // Load window: current + 1 ahead
      loadPage(page);
      if (page + 1 < (metadata?.totalImages ?? 0)) loadPage(page + 1);

      // Release 2+ behind
      if (page > 1) releasePage(page - 2);
    }
  }, [currentPage, metadata, loadPage, releasePage, setScrollVelocity]);

  const handleScrollEnd = useCallback(() => setScrollVelocity(0), [setScrollVelocity]);

  if (!isReady) {
    return (
      <View style={s.boot}>
        <Text style={s.bootText}>Initializing secure reader…</Text>
      </View>
    );
  }

  if (!metadata) {
    return (
      <View style={s.boot}>
        <Text style={s.errText}>Chapter not available offline</Text>
        <TouchableOpacity style={s.back} onPress={() => navigation.goBack()}>
          <Text style={s.backLabel}>← Back</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <SafeAreaView style={s.root}>
      <StatusBar hidden />
      <ScrollView
        style={s.scroll}
        onScroll={handleScroll}
        onScrollEndDrag={handleScrollEnd}
        onMomentumScrollEnd={handleScrollEnd}
        scrollEventThrottle={16}
        showsVerticalScrollIndicator={false}
        removeClippedSubviews
        overScrollMode="never"
      >
        {images.map((slot) => (
          <SecureImageViewer
            key={slot.index}
            mutatedData={slot.mutatedData}
            imageId={metadata.imageIds[slot.index] ?? ''}
            chunkIndex={slot.index}
            isLoading={slot.isLoading}
            error={slot.error}
            onRenderComplete={() => {
              // Preload next when current renders
              const next = slot.index + 1;
              if (next < images.length && !images[next]?.mutatedData && !images[next]?.isLoading) {
                loadPage(next);
              }
            }}
          />
        ))}
      </ScrollView>

      {/* Minimal, non-interactive page indicator */}
      <View style={s.indicator} pointerEvents="none">
        <Text style={s.indicatorText}>
          {currentPage + 1} / {metadata.totalImages}
        </Text>
      </View>
    </SafeAreaView>
  );
};

const s = StyleSheet.create({
  root:          { flex: 1, backgroundColor: '#000' },
  scroll:        { flex: 1 },
  boot:          { flex: 1, backgroundColor: '#000', justifyContent: 'center', alignItems: 'center' },
  bootText:      { color: '#333', fontFamily: 'monospace', fontSize: 12 },
  errText:       { color: '#662222', fontFamily: 'monospace', fontSize: 13, marginBottom: 16 },
  back:          { borderWidth: 1, borderColor: '#222', paddingHorizontal: 20, paddingVertical: 8, borderRadius: 3 },
  backLabel:     { color: '#444', fontSize: 13 },
  indicator:     { position: 'absolute', bottom: 12, right: 12, backgroundColor: 'rgba(0,0,0,0.6)',
                   paddingHorizontal: 7, paddingVertical: 3, borderRadius: 3 },
  indicatorText: { color: '#3a3a3a', fontSize: 10, fontFamily: 'monospace' },
});
