import React, { useEffect, useState } from 'react';
import { View, Text, ScrollView } from 'react-native';
import { AppBootstrap } from './src/core/AppBootstrap';
import ChapterScreen from './src/screens/ChapterScreen';

export default function App() {
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<any>(null);

  useEffect(() => {
    let mounted = true;

    (async () => {
      try {
        await AppBootstrap.initialize('user-1');
        if (mounted) setReady(true);
      } catch (e: any) {
        if (!mounted) return;

        console.log('BOOT ERROR:', e);

        setError({
          message: e?.message ?? 'No message',
          name: e?.name ?? 'UnknownError',
          stack: e?.stack ?? 'No stack trace',
          raw: JSON.stringify(e, Object.getOwnPropertyNames(e), 2),
        });
      }
    })();

    return () => {
      mounted = false;
      AppBootstrap.teardown();
    };
  }, []);

  if (error) {
    return (
      <ScrollView
        style={{ flex: 1, backgroundColor: '#000' }}
        contentContainerStyle={{ padding: 20 }}
      >
        <Text style={{ color: 'red', fontSize: 16, marginBottom: 10 }}>
          SECURITY INITIALIZATION FAILED
        </Text>

        <Text style={{ color: '#fff', marginBottom: 6 }}>
          Name: {error.name}
        </Text>

        <Text style={{ color: '#fff', marginBottom: 6 }}>
          Message: {error.message}
        </Text>

        <Text style={{ color: '#aaa', marginBottom: 6 }}>
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
      <View style={{ flex: 1, backgroundColor: '#000', justifyContent: 'center', alignItems: 'center' }}>
        <Text style={{ color: '#999' }}>Initializing secure reader...</Text>
      </View>
    );
  }

  return <ChapterScreen />;
}