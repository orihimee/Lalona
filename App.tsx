import React, { useEffect, useState } from 'react';
import { View, Text } from 'react-native';
import { AppBootstrap } from './src/core/AppBootstrap';
import ChapterScreen from './src/screens/ChapterScreen';

export default function App() {
  const [ready, setReady] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let mounted = true;

    (async () => {
      try {
        await AppBootstrap.initialize('user-1');
        if (mounted) setReady(true);
      } catch (e) {
        if (mounted) setFailed(true);
      }
    })();

    return () => {
      mounted = false;
      AppBootstrap.teardown();
    };
  }, []);

  if (failed) {
    return (
      <View style={{ flex: 1, backgroundColor: '#000', justifyContent: 'center', alignItems: 'center' }}>
        <Text style={{ color: 'red' }}>Security initialization failed</Text>
      </View>
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