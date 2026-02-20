import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  ScrollView,
  LogBox
} from 'react-native';
import { AppBootstrap } from './src/core/AppBootstrap';
import ChapterScreen from './src/screens/ChapterScreen';
import { Buffer } from 'buffer';

global.Buffer = Buffer;

// Optional: silence irrelevant warnings
LogBox.ignoreLogs(['Require cycle']);

type ErrorState = {
  name: string;
  message: string;
  stack?: string;
  raw?: string;
  time: string;
  phase: string;
};

export default function App() {
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<ErrorState | null>(null);

  useEffect(() => {
    let mounted = true;

    const handleGlobalError = (e: any, phase = 'GLOBAL') => {
      if (!mounted) return;

      console.log('🔥 GLOBAL ERROR:', e);

      setError({
        name: e?.name ?? 'UnknownError',
        message: e?.message ?? 'No message',
        stack: e?.stack ?? 'No stack',
        raw: JSON.stringify(e, Object.getOwnPropertyNames(e), 2),
        time: new Date().toISOString(),
        phase,
      });
    };

    // Catch unhandled JS errors
    const globalHandler = (error: any, isFatal?: boolean) => {
      handleGlobalError(error, isFatal ? 'FATAL' : 'UNHANDLED');
    };

    // @ts-ignore
    const defaultHandler = global.ErrorUtils?.getGlobalHandler?.();
    // @ts-ignore
    global.ErrorUtils?.setGlobalHandler?.(globalHandler);

    (async () => {
      try {
        await AppBootstrap.initialize('user-1');
        if (mounted) setReady(true);
      } catch (e: any) {
        handleGlobalError(e, 'BOOTSTRAP');
      }
    })();

    return () => {
      mounted = false;
      AppBootstrap.teardown();

      // Restore default handler
      // @ts-ignore
      if (defaultHandler) global.ErrorUtils?.setGlobalHandler(defaultHandler);
    };
  }, []);

  if (error) {
    return (
      <ScrollView
        style={{ flex: 1, backgroundColor: '#000' }}
        contentContainerStyle={{ padding: 20 }}
      >
        <Text style={{ color: 'red', fontSize: 18, marginBottom: 15 }}>
          ⚠ SECURITY / RUNTIME FAILURE
        </Text>

        <Text style={{ color: '#fff' }}>Phase: {error.phase}</Text>
        <Text style={{ color: '#fff' }}>Time: {error.time}</Text>
        <Text style={{ color: '#fff' }}>Name: {error.name}</Text>
        <Text style={{ color: '#fff' }}>Message: {error.message}</Text>

        <Text style={{ color: '#aaa', marginTop: 15 }}>
          Stack:
        </Text>
        <Text style={{ color: '#777', fontSize: 12 }}>
          {error.stack}
        </Text>

        <Text style={{ color: '#555', marginTop: 20 }}>
          Raw:
        </Text>
        <Text style={{ color: '#444', fontSize: 11 }}>
          {error.raw}
        </Text>
      </ScrollView>
    );
  }

  if (!ready) {
    return (
      <View
        style={{
          flex: 1,
          backgroundColor: '#000',
          justifyContent: 'center',
          alignItems: 'center',
        }}
      >
        <Text style={{ color: '#999' }}>
          Initializing secure reader...
        </Text>
      </View>
    );
  }

  return <ChapterScreen />;
}