const USB_DETECTOR_WS_URL = "ws://localhost:12345"
const SESSION_KEY = "workstation_fingerprint"

export interface MachineFingerprint {
  machine_id: string
  components: Record<string, string>
}

/**
 * Get the workstation fingerprint from usb_detector.py.
 *
 * 1. Returns cached value from sessionStorage if available.
 * 2. Otherwise opens a temporary WebSocket to usb_detector.py,
 *    authenticates, receives the MACHINE_FINGERPRINT event,
 *    caches it, and closes the connection.
 *
 * Throws if usb_detector.py is not running or the connection fails.
 */
export function fetchWorkstationFingerprint(): Promise<MachineFingerprint> {
  // Check cache first
  const stored = sessionStorage.getItem(SESSION_KEY)
  if (stored) {
    return Promise.resolve(JSON.parse(stored) as MachineFingerprint)
  }

  const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
  if (!userInfo?.authToken) {
    return Promise.reject(new Error("Not authenticated"))
  }

  return new Promise((resolve, reject) => {
    let settled = false
    const ws = new WebSocket(USB_DETECTOR_WS_URL)

    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true
        ws.close()
        reject(new Error("USB detector is not running. Start usb_detector.py on the target workstation first."))
      }
    }, 5000)

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "auth", token: userInfo.authToken }))
    }

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.event === "MACHINE_FINGERPRINT") {
          const fingerprint: MachineFingerprint = {
            machine_id: data.machine_id,
            components: data.components,
          }
          sessionStorage.setItem(SESSION_KEY, JSON.stringify(fingerprint))
          if (!settled) {
            settled = true
            clearTimeout(timeout)
            ws.close()
            resolve(fingerprint)
          }
        }
      } catch {
        // Ignore non-JSON or unrelated messages
      }
    }

    ws.onerror = () => {
      if (!settled) {
        settled = true
        clearTimeout(timeout)
        reject(new Error("USB detector is not running. Start usb_detector.py on the target workstation first."))
      }
    }

    ws.onclose = () => {
      if (!settled) {
        settled = true
        clearTimeout(timeout)
        reject(new Error("USB detector connection closed before fingerprint was received."))
      }
    }
  })
}
