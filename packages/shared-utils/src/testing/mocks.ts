// packages/shared-utils/src/testing/mocks.ts
// Mock implementations for testing external services and APIs
// Based on the domain interfaces and external service contracts

import { vi } from 'vitest';
import type {
  User,
  Host,
  Session,
  CreateUserRequest,
  UpdateUserRequest,
  CreateHostRequest,
  UpdateHostRequest,
  CreateSessionRequest,
  UpdateSessionRequest,
  PaginatedResponse,
  SearchResult,
} from '../types';
import { fixtures } from './fixtures';

// API Client Mocks
export const createMockApiClient = () => ({
  // User endpoints
  users: {
    create: vi.fn().mockResolvedValue(fixtures.user.create()),
    getById: vi.fn().mockResolvedValue(fixtures.user.create()),
    getByEmail: vi.fn().mockResolvedValue(fixtures.user.create()),
    update: vi.fn().mockResolvedValue(fixtures.user.create()),
    delete: vi.fn().mockResolvedValue({ success: true }),
    list: vi.fn().mockResolvedValue(fixtures.api.paginated(fixtures.user.list())),
    search: vi.fn().mockResolvedValue({
      items: fixtures.user.list(3),
      total: 3,
      query: 'test',
      searchTime: 25,
    } as SearchResult<User>),
  },

  // Host endpoints
  hosts: {
    create: vi.fn().mockResolvedValue(fixtures.host.create()),
    getById: vi.fn().mockResolvedValue(fixtures.host.create()),
    update: vi.fn().mockResolvedValue(fixtures.host.create()),
    delete: vi.fn().mockResolvedValue({ success: true }),
    list: vi.fn().mockResolvedValue(fixtures.api.paginated(fixtures.host.list())),
    search: vi.fn().mockResolvedValue({
      items: fixtures.host.list(2),
      total: 2,
      query: 'server',
      searchTime: 15,
    } as SearchResult<Host>),
    testConnection: vi.fn().mockResolvedValue({ success: true, responseTime: 50 }),
    updateHealth: vi.fn().mockResolvedValue({ success: true }),
  },

  // Session endpoints
  sessions: {
    create: vi.fn().mockResolvedValue(fixtures.session.create()),
    getById: vi.fn().mockResolvedValue(fixtures.session.create()),
    list: vi.fn().mockResolvedValue(fixtures.api.paginated(fixtures.session.list())),
    terminate: vi.fn().mockResolvedValue({ success: true }),
    getRecording: vi.fn().mockResolvedValue(new Blob(['mock recording data'])),
    getCommands: vi.fn().mockResolvedValue([
      fixtures.session.create().commandsExecuted[0],
    ]),
  },

  // Authentication endpoints
  auth: {
    login: vi.fn().mockResolvedValue({
      user: fixtures.user.create(),
      tokens: fixtures.auth.token(),
    }),
    register: vi.fn().mockResolvedValue({
      user: fixtures.user.pending(),
      message: 'Registration successful. Please verify your email.',
    }),
    refreshToken: vi.fn().mockResolvedValue(fixtures.auth.token()),
    logout: vi.fn().mockResolvedValue({ success: true }),
    verifyEmail: vi.fn().mockResolvedValue({ success: true }),
    requestPasswordReset: vi.fn().mockResolvedValue({ success: true }),
    resetPassword: vi.fn().mockResolvedValue({ success: true }),
    changePassword: vi.fn().mockResolvedValue({ success: true }),
  },

  // SSH Key endpoints
  sshKeys: {
    add: vi.fn().mockResolvedValue(fixtures.ssh.key()),
    list: vi.fn().mockResolvedValue([fixtures.ssh.key()]),
    delete: vi.fn().mockResolvedValue({ success: true }),
    validate: vi.fn().mockResolvedValue({
      valid: true,
      keyType: 'ssh-ed25519',
      bitLength: 256,
    }),
  },

  // Audit endpoints
  audit: {
    list: vi.fn().mockResolvedValue(fixtures.api.paginated([])),
    search: vi.fn().mockResolvedValue({
      items: [],
      total: 0,
      query: 'test',
      searchTime: 5,
    }),
    export: vi.fn().mockResolvedValue(new Blob(['mock audit data'])),
  },
});

// WebSocket Mock
export const createMockWebSocket = () => {
  const mockWebSocket = {
    send: vi.fn(),
    close: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
    readyState: WebSocket.OPEN,
    url: 'ws://localhost:8080/ws',
    protocol: '',
    extensions: '',
    bufferedAmount: 0,
    binaryType: 'blob' as BinaryType,
    onopen: null,
    onclose: null,
    onmessage: null,
    onerror: null,
    CONNECTING: WebSocket.CONNECTING,
    OPEN: WebSocket.OPEN,
    CLOSING: WebSocket.CLOSING,
    CLOSED: WebSocket.CLOSED,
  } as unknown as WebSocket;

  // Helper methods for testing
  const mockHelpers = {
    simulateOpen: () => {
      if (mockWebSocket.onopen) {
        mockWebSocket.onopen({} as Event);
      }
    },
    simulateMessage: (data: any) => {
      if (mockWebSocket.onmessage) {
        mockWebSocket.onmessage({
          data: JSON.stringify(data),
        } as MessageEvent);
      }
    },
    simulateError: (error: Error) => {
      if (mockWebSocket.onerror) {
        mockWebSocket.onerror({
          error,
        } as ErrorEvent);
      }
    },
    simulateClose: (code: number = 1000, reason: string = 'Normal closure') => {
      (mockWebSocket as any).readyState = WebSocket.CLOSED;
      if (mockWebSocket.onclose) {
        mockWebSocket.onclose({
          code,
          reason,
          wasClean: code === 1000,
        } as CloseEvent);
      }
    },
  };

  return { mockWebSocket, ...mockHelpers };
};

// Terminal/XTerm Mock
export const createMockTerminal = () => ({
  // Terminal properties
  rows: 24,
  cols: 80,
  element: document.createElement('div'),

  // Terminal methods
  open: vi.fn(),
  write: vi.fn(),
  writeln: vi.fn(),
  clear: vi.fn(),
  reset: vi.fn(),
  resize: vi.fn(),
  focus: vi.fn(),
  blur: vi.fn(),
  select: vi.fn(),
  selectAll: vi.fn(),
  clearSelection: vi.fn(),
  getSelection: vi.fn().mockReturnValue(''),
  scrollLines: vi.fn(),
  scrollPages: vi.fn(),
  scrollToTop: vi.fn(),
  scrollToBottom: vi.fn(),
  refresh: vi.fn(),
  dispose: vi.fn(),

  // Event handling
  onData: vi.fn(),
  onKey: vi.fn(),
  onResize: vi.fn(),
  onScroll: vi.fn(),
  onSelectionChange: vi.fn(),
  onRender: vi.fn(),

  // Addons
  loadAddon: vi.fn(),

  // Buffer
  buffer: {
    active: {
      cursorX: 0,
      cursorY: 0,
      viewportY: 0,
      baseY: 0,
      length: 24,
      getLine: vi.fn().mockReturnValue({
        translateToString: vi.fn().mockReturnValue(''),
      }),
    },
    normal: {
      cursorX: 0,
      cursorY: 0,
      viewportY: 0,
      baseY: 0,
      length: 24,
    },
    alternate: {
      cursorX: 0,
      cursorY: 0,
      viewportY: 0,
      baseY: 0,
      length: 24,
    },
  },

  // Options
  options: {
    fontSize: 14,
    fontFamily: 'monospace',
    theme: {
      background: '#000000',
      foreground: '#ffffff',
    },
  },
});

// Local Storage Mock
export const createMockLocalStorage = () => {
  let store: Record<string, string> = {};

  return {
    getItem: vi.fn((key: string) => store[key] || null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      store = {};
    }),
    length: 0,
    key: vi.fn((index: number) => {
      const keys = Object.keys(store);
      return keys[index] || null;
    }),
  };
};

// Crypto Mock (for testing encryption/hashing)
export const createMockCrypto = () => ({
  subtle: {
    encrypt: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    decrypt: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    sign: vi.fn().mockResolvedValue(new ArrayBuffer(64)),
    verify: vi.fn().mockResolvedValue(true),
    digest: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    generateKey: vi.fn().mockResolvedValue({}),
    deriveKey: vi.fn().mockResolvedValue({}),
    deriveBits: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    importKey: vi.fn().mockResolvedValue({}),
    exportKey: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    wrapKey: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    unwrapKey: vi.fn().mockResolvedValue({}),
  },
  getRandomValues: vi.fn((array: Uint8Array) => {
    for (let i = 0; i < array.length; i++) {
      array[i] = Math.floor(Math.random() * 256);
    }
    return array;
  }),
  randomUUID: vi.fn(() => '123e4567-e89b-12d3-a456-426614174000'),
});

// File System Mock (for testing file uploads/downloads)
export const createMockFile = (
  name: string = 'test.txt',
  content: string = 'test content',
  type: string = 'text/plain'
): File => {
  const file = new File([content], name, { type });
  return file;
};

export const createMockFileReader = () => ({
  readAsText: vi.fn(),
  readAsDataURL: vi.fn(),
  readAsArrayBuffer: vi.fn(),
  readAsBinaryString: vi.fn(),
  abort: vi.fn(),
  result: null,
  error: null,
  readyState: FileReader.DONE,
  onload: null,
  onerror: null,
  onabort: null,
  onloadstart: null,
  onloadend: null,
  onprogress: null,
  EMPTY: FileReader.EMPTY,
  LOADING: FileReader.LOADING,
  DONE: FileReader.DONE,
  addEventListener: vi.fn(),
  removeEventListener: vi.fn(),
  dispatchEvent: vi.fn(),
});

// Notification API Mock
export const createMockNotification = () => {
  const mockNotification = vi.fn().mockImplementation((title: string, options?: NotificationOptions) => ({
    title,
    body: options?.body || '',
    icon: options?.icon || '',
    tag: options?.tag || '',
    data: options?.data || null,
    onclick: null,
    onclose: null,
    onerror: null,
    onshow: null,
    close: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));

  mockNotification.permission = 'granted';
  mockNotification.requestPermission = vi.fn().mockResolvedValue('granted');

  return mockNotification;
};

// Date Mock (for consistent time in tests)
export const createMockDate = (fixedDate: string = '2023-10-01T10:00:00.000Z') => {
  const mockDate = new Date(fixedDate);
  const originalDate = Date;

  const MockDateConstructor = vi.fn().mockImplementation((...args: any[]) => {
    if (args.length === 0) {
      return new originalDate(fixedDate);
    }
    return new (originalDate as { new(...args: any[]): Date })(...args);
  });

  MockDateConstructor.now = vi.fn(() => mockDate.getTime());
  MockDateConstructor.parse = originalDate.parse;
  MockDateConstructor.UTC = originalDate.UTC;
  MockDateConstructor.prototype = originalDate.prototype;

  return {
    mockDate: MockDateConstructor as any,
    fixedTimestamp: mockDate.getTime(),
    fixedISOString: mockDate.toISOString(),
  };
};

// Router Mock (for React Router or Next.js)
export const createMockRouter = () => ({
  push: vi.fn(),
  replace: vi.fn(),
  back: vi.fn(),
  forward: vi.fn(),
  refresh: vi.fn(),
  prefetch: vi.fn(),
  pathname: '/',
  query: {},
  asPath: '/',
  basePath: '',
  route: '/',
  isReady: true,
  isPreview: false,
  isLocaleDomain: true,
  events: {
    on: vi.fn(),
    off: vi.fn(),
    emit: vi.fn(),
  },
});

// React Hook Mocks
export const createMockUseState = <T>(initialValue: T) => {
  let state = initialValue;
  const setState = vi.fn((newValue: T | ((prev: T) => T)) => {
    if (typeof newValue === 'function') {
      state = (newValue as (prev: T) => T)(state);
    } else {
      state = newValue;
    }
  });

  return [() => state, setState] as const;
};

export const createMockUseEffect = () => vi.fn();

export const createMockUseCallback = () => vi.fn((fn: Function) => fn);

export const createMockUseMemo = () => vi.fn((fn: Function) => fn());

// HTTP Client Mock (Fetch/Axios)
export const createMockFetch = () => {
  const mockFetch = vi.fn();

  // Success response
  const mockSuccessResponse = (data: any, status: number = 200) => {
    mockFetch.mockResolvedValueOnce({
      ok: status >= 200 && status < 300,
      status,
      statusText: status === 200 ? 'OK' : 'Error',
      headers: new Headers({
        'content-type': 'application/json',
      }),
      json: vi.fn().mockResolvedValue(data),
      text: vi.fn().mockResolvedValue(JSON.stringify(data)),
      blob: vi.fn().mockResolvedValue(new Blob([JSON.stringify(data)])),
    });
  };

  // Error response
  const mockErrorResponse = (status: number = 500, message: string = 'Internal Server Error') => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status,
      statusText: message,
      headers: new Headers({
        'content-type': 'application/json',
      }),
      json: vi.fn().mockResolvedValue({
        error: message,
        code: status,
      }),
      text: vi.fn().mockResolvedValue(JSON.stringify({
        error: message,
        code: status,
      })),
    });
  };

  // Network error
  const mockNetworkError = () => {
    mockFetch.mockRejectedValueOnce(new Error('Network error'));
  };

  return {
    mockFetch,
    mockSuccessResponse,
    mockErrorResponse,
    mockNetworkError,
  };
};

// Performance Mock
export const createMockPerformance = () => ({
  now: vi.fn(() => Date.now()),
  mark: vi.fn(),
  measure: vi.fn(),
  clearMarks: vi.fn(),
  clearMeasures: vi.fn(),
  getEntries: vi.fn().mockReturnValue([]),
  getEntriesByName: vi.fn().mockReturnValue([]),
  getEntriesByType: vi.fn().mockReturnValue([]),
});

// Intersection Observer Mock
export const createMockIntersectionObserver = () => {
  const mockObserver = vi.fn().mockImplementation(() => ({
    observe: vi.fn(),
    unobserve: vi.fn(),
    disconnect: vi.fn(),
    root: null,
    rootMargin: '0px',
    thresholds: [0],
  }));

  return mockObserver;
};

// Resize Observer Mock
export const createMockResizeObserver = () => {
  const mockObserver = vi.fn().mockImplementation(() => ({
    observe: vi.fn(),
    unobserve: vi.fn(),
    disconnect: vi.fn(),
  }));

  return mockObserver;
};

// Media Query Mock
export const createMockMediaQueryList = (matches: boolean = false) => ({
  matches,
  media: '(min-width: 768px)',
  onchange: null,
  addListener: vi.fn(),
  removeListener: vi.fn(),
  addEventListener: vi.fn(),
  removeEventListener: vi.fn(),
  dispatchEvent: vi.fn(),
});

// Canvas Mock (for drawing/charting tests)
export const createMockCanvas = () => {
  const canvas = document.createElement('canvas');
  const context = {
    fillRect: vi.fn(),
    clearRect: vi.fn(),
    getImageData: vi.fn(() => ({ data: new Uint8ClampedArray(4) })),
    putImageData: vi.fn(),
    createImageData: vi.fn(() => ({ data: new Uint8ClampedArray(4) })),
    setTransform: vi.fn(),
    drawImage: vi.fn(),
    save: vi.fn(),
    restore: vi.fn(),
    beginPath: vi.fn(),
    closePath: vi.fn(),
    moveTo: vi.fn(),
    lineTo: vi.fn(),
    clip: vi.fn(),
    quadraticCurveTo: vi.fn(),
    arc: vi.fn(),
    fill: vi.fn(),
    stroke: vi.fn(),
    strokeText: vi.fn(),
    fillText: vi.fn(),
    measureText: vi.fn(() => ({ width: 10 })),
    transform: vi.fn(),
    translate: vi.fn(),
    scale: vi.fn(),
    rotate: vi.fn(),
    globalCompositeOperation: 'source-over',
    fillStyle: '#000000',
    strokeStyle: '#000000',
    lineWidth: 1,
    lineCap: 'butt' as CanvasLineCap,
    lineJoin: 'miter' as CanvasLineJoin,
    font: '10px sans-serif',
    textAlign: 'start' as CanvasTextAlign,
    textBaseline: 'alphabetic' as CanvasTextBaseline,
  };

  canvas.getContext = vi.fn(() => context);
  return { canvas, context };
};

// Test Environment Setup Helpers
export const setupMockEnvironment = () => {
  // Global mocks
  Object.defineProperty(window, 'localStorage', {
    value: createMockLocalStorage(),
  });

  Object.defineProperty(window, 'crypto', {
    value: createMockCrypto(),
  });

  Object.defineProperty(window, 'Notification', {
    value: createMockNotification(),
  });

  Object.defineProperty(window, 'performance', {
    value: createMockPerformance(),
  });

  Object.defineProperty(window, 'IntersectionObserver', {
    value: createMockIntersectionObserver(),
  });

  Object.defineProperty(window, 'ResizeObserver', {
    value: createMockResizeObserver(),
  });

  Object.defineProperty(window, 'matchMedia', {
    value: vi.fn().mockImplementation((query: string) => createMockMediaQueryList()),
  });

  // Mock fetch globally
  const { mockFetch } = createMockFetch();
  globalThis.fetch = mockFetch;

  return {
    cleanup: () => {
      vi.restoreAllMocks();
    },
  };
};

// Export all mocks as a collection
export const mocks = {
  api: createMockApiClient,
  websocket: createMockWebSocket,
  terminal: createMockTerminal,
  localStorage: createMockLocalStorage,
  crypto: createMockCrypto,
  file: createMockFile,
  fileReader: createMockFileReader,
  notification: createMockNotification,
  date: createMockDate,
  router: createMockRouter,
  fetch: createMockFetch,
  performance: createMockPerformance,
  intersectionObserver: createMockIntersectionObserver,
  resizeObserver: createMockResizeObserver,
  mediaQuery: createMockMediaQueryList,
  canvas: createMockCanvas,
  setup: setupMockEnvironment,
};