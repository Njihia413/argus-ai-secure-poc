"use client";

import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { io, Socket } from 'socket.io-client';

interface YubiKey {
  serial: number;
  version: string;
  form_factor: string;
  device_type: string;
  is_fips: boolean;
  is_sky: boolean;
}

interface YubiKeyDetectionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelect: (key: YubiKey) => void;
}

export function YubiKeyDetectionModal({ isOpen, onClose, onSelect }: YubiKeyDetectionModalProps) {
  const [yubiKeys, setYubiKeys] = useState<YubiKey[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    // Connect to the Flask-SocketIO server
    const socket: Socket = io("http://localhost:5000", {
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      transports: ['websocket'],
    });

    function onConnect() {
      console.log('Connected to WebSocket server');
      setIsConnected(true);
    }

    function onDisconnect() {
      console.log('Disconnected from WebSocket server');
      setIsConnected(false);
    }

    function onYubiKeysUpdate(data: { yubikeys: YubiKey[] }) {
      console.log('Received yubikeys_update:', data);
      setYubiKeys(data.yubikeys);
    }

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('yubikeys_update', onYubiKeysUpdate);

    // Fetch the initial list of keys when the modal opens
    const fetchInitialKeys = async () => {
      try {
        const response = await fetch('http://localhost:5000/api/security-keys/detect-yubikeys');
        const data = await response.json();
        if (data.success) {
          setYubiKeys(data.yubikeys);
        }
      } catch (error) {
        console.error("Failed to fetch initial YubiKeys", error);
      }
    };
    fetchInitialKeys();

    return () => {
      socket.disconnect();
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('yubikeys_update', onYubiKeysUpdate);
    };
  }, [isOpen]);

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[625px] font-montserrat">
        <DialogHeader>
          <DialogTitle>Detect YubiKey</DialogTitle>
          <DialogDescription>
            {isConnected ? 'Please insert your YubiKey. It will appear in the list below.' : 'Connecting to detection service...'}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          {yubiKeys.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Serial Number</TableHead>
                  <TableHead>Model</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {yubiKeys.map((key) => (
                  <TableRow key={key.serial}>
                    <TableCell>{key.serial}</TableCell>
                    <TableCell>{key.form_factor}</TableCell>
                    <TableCell>{key.version}</TableCell>
                    <TableCell>
                      <Button onClick={() => onSelect(key)}>Select</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-center text-gray-500">No YubiKeys detected. Please insert a key.</p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}