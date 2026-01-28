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
import { useYubiKeyDetection, YubiKey } from '@/app/hooks/use-yubikey-detection';

interface YubiKeyDetectionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelect: (key: YubiKey) => void;
}

export function YubiKeyDetectionModal({ isOpen, onClose, onSelect }: YubiKeyDetectionModalProps) {
  const { detectedKeys: yubiKeys, isConnected } = useYubiKeyDetection(isOpen);


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