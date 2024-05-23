'use client';

import { OpenloginUserInfo } from '@toruslabs/openlogin-utils';
import {
  ADAPTER_EVENTS,
  IProvider,
  SafeEventEmitterProvider,
} from '@web3auth/base';
import { EthereumPrivateKeyProvider } from '@web3auth/ethereum-provider';
import { IWeb3Auth, Web3Auth } from '@web3auth/single-factor-auth';
import clsx from 'clsx';
import React, { useEffect, useState } from 'react';
import Web3 from 'web3';

import PasskeyService from '@/lib/passkeyService';

type Log = string;

export default function ComponentPage() {
  const [mode, setMode] = React.useState<'dark' | 'light'>('light');
  function toggleMode() {
    return mode === 'dark' ? setMode('light') : setMode('dark');
  }
  const [provider, setProvider] = useState<IProvider | null>(null);
  const [web3authSFAuth, setWeb3authSFAuth] = useState<IWeb3Auth | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const [logs, setLogs] = useState<Log[]>([]);
  const [privateKey, setPrivateKey] = useState<string>('');

  const clientId =
    'BPi5PB_UiIZ-cPz1GtV5i1I2iOSOHuimiXBI0e-Oe_u6X3oVAbCiAZOTEBtTXw4tsluTITPqA8zMsfxIKMjiqNQ'; // get from https://dashboard.web3auth.io
  const verifier = 'passkey-sapphire-mainnet';
  const chainConfig = {
    rpcTarget: 'https://polygon-rpc.com',
    chainId: '0x89', // hex chain id
    chainNamespace: 'eip155' as any,
    ticker: 'matic',
    tickerName: 'matic',
  };

  const passkeyService = new PasskeyService({
    buildEnv: 'development',
    rpID: 'localhost',
    rpName: 'globalWallet',
    // rpOrigin: 'https://wildcat-endless-basically.ngrok-free.app',
    verifier: verifier,
    web3authClientId: clientId,
    web3authNetwork: 'sapphire_mainnet',
    // serverTimeOffset: 60,
  });
  useEffect(() => {
    const init = async () => {
      const provider = new EthereumPrivateKeyProvider({
        config: { chainConfig },
      });
      const web3authSfa = new Web3Auth({
        clientId, // Get your Client ID from Web3Auth Dashboard
        web3AuthNetwork: 'sapphire_devnet', // ["cyan", "testnet"]
        usePnPKey: true, // Setting this to true returns the same key as PnP Web SDK, By default, this SDK returns CoreKitKey.
        // metadataHost: 'https://metadata-testing.tor.us',
        privateKeyProvider: provider,
      });
      web3authSfa.on(ADAPTER_EVENTS.CONNECTED, async (data: any) => {
        addLog(`"sfa:connected", ${data}`);
        addLog(`"sfa:state", ${web3authSfa?.state}`);
        setProvider(web3authSfa.provider);
        const userInfo = await web3authSfa?.getUserInfo();
        addLog(`userinfo , ${userInfo}`);
        // setVerifierId(userInfo?.verifierId as string)
      });
      web3authSfa.on(ADAPTER_EVENTS.DISCONNECTED, () => {
        addLog(`"sfa:disconnected"`);
        setWeb3authSFAuth(web3authSfa);
      });
      setWeb3authSFAuth(web3authSfa);
      await web3authSfa.init();
    };
    init();
  }, []);

  const addLog = (message: Log) => {
    setLogs((prevLogs) => [...prevLogs, message]);
  };

  const textColor = mode === 'dark' ? 'text-gray-300' : 'text-gray-600';

  async function registerPasskey(username = 'testtemp') {
    // await passkeyService.registerCredential({});
    const result = await passkeyService.initiateRegistration({
      oAuthVerifier: 'verifier',
      oAuthVerifierId: 'verifierId',
      username: username as string,
      signatures: [],
      passkeyToken: '',
    });
    console.log({ result });
    const verificationResult = await passkeyService.registerPasskey({
      verificationResponse: result,
      signatures: [],
      passkeyToken: 'this.authToken',
    });
    console.log({ verificationResult });
  }

  const getUserInfo = async () => {
    console.log({ web3authSFAuth });
    if (web3authSFAuth && web3authSFAuth?.connected) {
      const userInfo = await web3authSFAuth?.getUserInfo();
      addLog(`"user info", ${JSON.stringify(userInfo, null, 2)}`);
      return;
    }
  };

  async function loginPasskey() {
    addLog('loginPasskey');
    await passkeyService.getCredential({});

    const loginResult = await passkeyService.loginUser('testtemp');
    setPrivateKey(loginResult?.data.privateKey || '');
    const userInfo: OpenloginUserInfo = {
      typeOfLogin: 'passkey',
      verifierId: 'testtemp',
      verifier: verifier,
    };
    await web3authSFAuth?._finalizeLogin({
      privKey: loginResult?.data.privateKey as string,
      userInfo,
      signatures: loginResult?.data.sessionSignatures,
    });
    console.log(loginResult);
    addLog('loginResult');
    addLog(JSON.stringify(loginResult, null, 2));
  }

  function socialLogin(): void {
    console.log('socialLogin');
  }

  function signWithRegisteredPasskey(): void {
    console.log('signWithRegisteredPasskey');
  }

  function signWithLoginPasskey(): void {
    console.log('signWithLoginPasskey');
  }

  const signEthMessage = async (provider: SafeEventEmitterProvider) => {
    const web3 = new Web3(provider);
    const accounts = await web3.eth.getAccounts();
    // hex message
    const message =
      '0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad';
    const signature = await web3.eth.sign(message, accounts[0]);
    return signature;
  };

  async function signMessage() {
    const provider = await EthereumPrivateKeyProvider.getProviderInstance();
    const signedMessage = await signEthMessage(provider);
    addLog(JSON.stringify(signedMessage));
  }

  return (
    <main
      className={clsx(
        'min-h-screen',
        mode === 'dark' ? 'bg-gray-900 text-white' : 'bg-white text-black'
      )}
    >
      <div className='container mx-auto p-4 flex'>
        <div className='w-1/3 p-4 bg-gray-100 dark:bg-gray-800 rounded-lg shadow-md'>
          <h1 className='text-2xl font-semibold mb-4'>Built-in Components</h1>
          <div className='space-y-4'>
            <Button onClick={() => registerPasskey('testtemp')}>
              Register with passkey
            </Button>
            <Button onClick={() => loginPasskey()}>Login with passkey</Button>
            <Button onClick={signMessage}>Sign Message</Button>
            <Button onClick={getUserInfo}>getUserInfo</Button>
            <Button
              onClick={toggleMode}
              variant={mode === 'dark' ? 'light' : 'dark'}
            >
              Set to {mode === 'dark' ? 'light' : 'dark'}
            </Button>
            {/* <Button onClick={signWithRegisteredPasskey}>Sign with registered passkey</Button>
            <Button onClick={signWithLoginPasskey}>Sign with login passkey</Button> */}
          </div>
        </div>
        <div className='w-2/3 p-4 bg-gray-100 dark:bg-gray-800 rounded-lg shadow-md ml-4'>
          <h2 className='text-xl font-semibold mb-4'>Console</h2>
          <div className='h-96 overflow-y-scroll border p-2 bg-white dark:bg-gray-900 text-black dark:text-white rounded'>
            {logs.map((log, index) => (
              <p key={index}>{log}</p>
            ))}
          </div>
        </div>
      </div>
    </main>
  );
}

type ButtonProps = {
  onClick: () => void;
  children?: React.ReactNode;
  variant?: 'light' | 'dark';
};

const Button: React.FC<ButtonProps> = ({ onClick, children, variant }) => {
  const baseStyle = 'w-full py-2 px-4 rounded transition';
  const variantStyle =
    variant === 'dark'
      ? 'bg-black text-white hover:bg-gray-700'
      : 'bg-white text-black border hover:bg-gray-200';
  const primaryColor = 'bg-[#4779ff] text-white hover:bg-[#3b66cc]';
  return (
    <button
      onClick={onClick}
      className={`${baseStyle} ${
        variant === 'dark' ? primaryColor : variantStyle
      }`}
    >
      {children}
    </button>
  );
};

const colorList = [
  'slate',
  'gray',
  'zinc',
  'neutral',
  'stone',
  'red',
  'orange',
  'amber',
  'yellow',
  'lime',
  'green',
  'emerald',
  'teal',
  'cyan',
  'sky',
  'blue',
  'indigo',
  'violet',
  'purple',
  'fuchsia',
  'pink',
  'rose',
] as const;
