/* Content for the landing page and the lab. Everything the page says about behaviour is backed by a test; the output in
   the tour is recorded from the running service (scripts/record-transcripts.ts) and a test fails if it drifts. */
window.SITE = {
  name: 'nightwatch-secops',
  short: 'Nightwatch',
  title: 'nightwatch-secops · a security-operations engine whose log notices when it is edited',
  logo: 'radar',
  repo: 'https://github.com/MenoDK/nightwatch-secops',
  accent: {
    light: { fill: '#e8a317', ink: '#7a4d00', on: '#2a1a00', soft: '#fdf1d6', onNavy: '#ffc857' },
    dark: { fill: '#f0b429', ink: '#ffd27a', on: '#241800', soft: '#3a2a08', onNavy: '#ffc857' },
  },
  loading: {
    context: 'Security operations',
    title: 'Lighting the lamp',
    text: 'Checking the audit chain, the stores and the watch.',
    icon: 'radar',
    satellites: ['hash', 'lock', 'eye'],
    foot: 'Local demo · one service, PostgreSQL and Redis',
    sketch: 'M12 104C48 104 66 104 88 64S128 144 168 104 226 104 250 104 292 36 330 104',
  },
  lab: { href: 'lab.html', cta: 'Enter the lab', signin: 'Sign in' },
  auth: { header: 'x-api-key' },

  hero: {
    eyebrow: 'Security operations · tamper-evident, deceptive, human-gated',
    lead: 'Know when you are being attacked',
    soft: 'and prove what happened afterwards.',
    text: 'A security-operations engine for web applications. It writes every event into an audit log that notices when it is edited, scores risk with caps, sets traps that no honest visitor touches, refuses the usual attacks at the door, and lets an analyst suggest what to block while a person with a second factor decides.',
    primary: { label: 'Open the lab', href: 'lab.html' },
    secondary: { label: 'See how it works', href: '#tour', icon: 'layers' },
    pilot: 'Runs on your laptop · one service, PostgreSQL and Redis, no accounts',
    proof: [
      { icon: 'hash', a: 'The log is chained', b: 'edit a row and it names which' },
      { icon: 'flask', a: 'Every defence has a test', b: 'and a mutant that removes it' },
    ],
    top: ['NIGHTWATCH', 'Notices. Proves. Asks first.'],
    status: { icon: 'radar', small: 'Last verdict', strong: 'Trap touched at 02:14. Address blocked. A person approved the rest.' },
    art: `<svg viewBox="0 50 500 620" role="img" aria-label="A watchtower at night. A lamp at the top sweeps a beam across the sky towards the moon. At the foot of the tower a chain of five numbered blocks runs left to right; the fourth is marked as edited. To the left a honey jar is marked as a trap, and to the right a card reads: proposal, block one address, needs a person.">
      <g class="a-line"><path d="M0 120H500M0 240H500M0 360H500M0 480H500M0 600H500M100 30V700M250 30V700M400 30V700"/></g>
      <circle cx="392" cy="150" r="64" class="a-soft"/>
      <circle cx="414" cy="136" r="52" class="a-body"/>
      <g class="a-accent-s"><circle cx="70" cy="110" r="3"/><circle cx="150" cy="84" r="2.4"/><circle cx="212" cy="132" r="3"/><circle cx="318" cy="92" r="2.4"/><circle cx="470" cy="244" r="3"/><circle cx="44" cy="226" r="2.4"/></g>

      <path d="M262 238L488 160V330Z" class="a-soft"/>
      <g>
        <path d="M222 250h56l16 214h-88z" class="a-body"/>
        <path d="M222 250h56l16 214h-88z" class="a-line"/>
        <path d="M236 312h28M232 366h36M228 420h44" class="a-line"/>
        <rect x="238" y="262" width="24" height="28" rx="4" class="a-line"/>
        <rect x="226" y="214" width="48" height="36" rx="6" class="a-body"/>
        <rect x="226" y="214" width="48" height="36" rx="6" class="a-line"/>
        <circle cx="250" cy="232" r="9" class="a-accent pulse"/>
        <path d="M218 214h64l-32-30z" class="a-body"/>
        <path d="M218 214h64l-32-30z" class="a-line"/>
        <text x="250" y="170" text-anchor="middle" class="a-text">THE WATCH</text>
      </g>

      <g>
        <rect x="26" y="344" width="92" height="104" rx="16" class="a-body"/>
        <path d="M44 364h56" class="a-line"/>
        <path d="M40 380c0-8 12-12 32-12s32 4 32 12v44c0 12-12 18-32 18s-32-6-32-18z" class="a-line"/>
        <path d="M44 396c14 8 36 8 56 0" class="a-accent-s"/>
        <text x="72" y="334" text-anchor="middle" class="a-text">TRAP</text>
        <text x="72" y="468" text-anchor="middle" class="a-text-s">one touch, a verdict</text>
      </g>

      <g>
        <rect x="346" y="344" width="132" height="104" rx="16" class="a-body"/>
        <path d="M346 376h132" class="a-line"/>
        <text x="362" y="366" class="a-text-s">PROPOSAL</text>
        <text x="362" y="398" class="a-text-s">block 198.51.100.200</text>
        <text x="362" y="418" class="a-text-s">4 rows of evidence</text>
        <rect x="362" y="426" width="100" height="14" rx="7" class="a-line"/>
        <circle cx="372" cy="433" r="4" class="a-accent pulse"/>
        <text x="384" y="437" class="a-text-s">needs a person</text>
      </g>

      <g>
        <text x="250" y="516" text-anchor="middle" class="a-text">AUDIT CHAIN</text>
        <path d="M80 574H420" class="a-dash"/>
        <g>
          <rect x="30" y="546" width="70" height="56" rx="10" class="a-body"/><text x="65" y="570" text-anchor="middle" class="a-text-s">#1</text><text x="65" y="588" text-anchor="middle" class="a-text-s">9f3a…</text>
          <rect x="112" y="546" width="70" height="56" rx="10" class="a-body"/><text x="147" y="570" text-anchor="middle" class="a-text-s">#2</text><text x="147" y="588" text-anchor="middle" class="a-text-s">c71e…</text>
          <rect x="194" y="546" width="70" height="56" rx="10" class="a-body"/><text x="229" y="570" text-anchor="middle" class="a-text-s">#3</text><text x="229" y="588" text-anchor="middle" class="a-text-s">02bd…</text>
          <rect x="276" y="546" width="70" height="56" rx="10" class="a-bad-f"/><text x="311" y="570" text-anchor="middle" class="a-text-s">#4</text><text x="311" y="588" text-anchor="middle" class="a-text-s">edited</text>
          <rect x="358" y="546" width="70" height="56" rx="10" class="a-body"/><text x="393" y="570" text-anchor="middle" class="a-text-s">#5</text><text x="393" y="588" text-anchor="middle" class="a-text-s">e8d0…</text>
        </g>
        <path d="M100 574h12M182 574h12M264 574h12M346 574h12" class="a-accent-s"/>
        <text x="250" y="636" text-anchor="middle" class="a-text-s">each row signs the one before it</text>
      </g>
    </svg>`,
  },

  principles: {
    lead: ['Built to be doubted', 'by the person it protects.'],
    items: [
      ['hash', 'Chains the log'],
      ['eye', 'Sets traps'],
      ['key', 'Asks a person'],
      ['flask', 'Proven by tests'],
    ],
  },

  tour: {
    eyebrow: 'A tour of the whole thing',
    title: ['Five things that happen', 'on a bad night.'],
    text: 'Pick a tab. The output below is recorded from the running service with fictional data; a test fails if it ever stops being true.',
    tag: 'Recorded output',
    tabs: [
      {
        id: 'chain',
        label: 'Audit',
        icon: 'hash',
        title: 'The log that notices it was edited.',
        text: 'Every row carries a keyed hash of the row before it, so editing, deleting or cutting off rows names the damage. Someone who also holds the key passes on their own and fails only against a receipt kept elsewhere.',
        lab: 'lab.html#audit',
        transcript: (window.TRANSCRIPTS || {}).chain || '',
      },
      {
        id: 'traps',
        label: 'Traps',
        icon: 'eye',
        title: 'Some doors only an intruder opens.',
        text: 'A sign-in as an account no customer has, a record no screen shows: one touch is a verdict. The address is out and everyone else is untouched.',
        lab: 'lab.html#attack',
        transcript: (window.TRANSCRIPTS || {}).traps || '',
      },
      {
        id: 'gate',
        label: 'Humans',
        icon: 'key',
        title: 'A stolen API key can read everything and change nothing.',
        text: 'Changing what the application lets through takes the operators’ network and a code from an authenticator. A code works once, wrong ones lock the seat, and renaming yourself does not reset the count.',
        lab: 'lab.html#humans',
        transcript: (window.TRANSCRIPTS || {}).gate || '',
      },
      {
        id: 'guards',
        label: 'Guards',
        icon: 'shield',
        title: 'Decide on what the input means, not on how it looks.',
        text: 'An address written as one integer is still 127.0.0.1, and a name with one private record is still private. A webhook signature covers the time, the route and the bytes. A typo is not an attack and is not recorded as one.',
        lab: 'lab.html#guards',
        transcript: (window.TRANSCRIPTS || {}).guards || '',
      },
      {
        id: 'analyst',
        label: 'Analyst',
        icon: 'bot',
        title: 'It proposes. A person decides.',
        text: 'The analyst reads the evidence and queues suggestions with the audit rows they rest on. Nothing it says is believed unless the evidence backs it, and approving takes the same human gate.',
        lab: 'lab.html#analyst',
        transcript: (window.TRANSCRIPTS || {}).analyst || '',
      },
    ],
    modulesTitle: 'Everything in the box.',
    modulesNote: 'Each one has a test file and a place in the lab',
    modules: [
      ['hash', 'Hash-chained audit log', 'HMAC over each row and the one before, a head row that remembers where the chain ends, receipts signed with the same key and five named kinds of damage.'],
      ['gauge', 'Capped risk score', 'A table of weights with a ceiling per signal, the score without overrides shown next to the score with them, and events that cannot be talked away.'],
      ['eye', 'Honeytokens and canaries', 'An account and a record that no honest request touches. One touch blocks the address; the lockdown is a setting, not a reflex.'],
      ['shield', 'Guards', 'SSRF, open redirects, signed webhooks, prompt injection and spoofed forwarding headers. Each decides on the parsed value and each refusal is evidence.'],
      ['key', 'Human gate', 'The operators’ network, then a one-time code. One bucket for wrong codes and a lockout that only a person releases.'],
      ['bot', 'An analyst that proposes', 'Local rules or any OpenAI-compatible model, validated against the evidence, never shown free text from the logs and never able to act.'],
    ],
    transparency: {
      strong: 'Honest about the demo.',
      text: 'The protected application is a stand-in in the same process, the geolocation table is three documentation ranges, and the operator’s code is on screen because the lab may do that. The remote analyst was tested against a fake endpoint, not a real model. The limitations list in the README is complete.',
    },
  },

  challenges: {
    eyebrow: 'The hard parts',
    title: ['Go on,', 'try to cover your tracks.'],
    text: 'These are seven things that are easy to claim and hard to get right. Each has a recipe, what you should see, and a button that opens the lab on that exact tab.',
    items: [
      {
        label: 'Edit the log',
        icon: 'hash',
        access: 'Lab · Audit',
        title: 'Change a row, then cover your tracks.',
        text: 'A log you can edit quietly is decoration.',
        steps: [
          'In <code>Attack</code>, run <code>Credential stuffing</code> so the chain has some history.',
          'In <code>Audit</code>, press “Take a receipt”, then “Edit a row” and “Verify”.',
          'Press “Start over”, run Stuffing again, take a receipt, and this time press “Rewrite with the key”. Verify, then “Verify against the receipt”.',
        ],
        expect: 'The edit names the exact row (<code>row_hash_mismatch</code>). The rewrite passes on its own, because the chain is consistent again, and fails against the receipt with <code>anchor_mismatch</code>.',
        lab: 'lab.html#audit',
      },
      {
        label: 'Touch a trap',
        icon: 'eye',
        access: 'Lab · Attack',
        title: 'Sign in as an account nobody has.',
        text: 'Honest people never do this, so once is enough.',
        steps: [
          'In <code>Attack</code>, press “Honeytoken”.',
          'Request the resource from the same address, then from another one.',
          'Open <code>Audit</code> and read the rows the trap wrote.',
        ],
        expect: 'The first address answers <code>403 blocked</code>, the other is untouched, and the chain holds <code>honeytoken_trip</code> followed by <code>ip_blocked</code>, each with the address.',
        lab: 'lab.html#attack',
      },
      {
        label: 'Use a stolen key',
        icon: 'key',
        access: 'Lab · Humans',
        title: 'Try to change the world with only the API key.',
        text: 'The key that leaks most easily should be the one that can do least.',
        steps: [
          'In <code>Humans</code>, act from “the internet” with a correct code and press “Block”.',
          'Act from “the operators’ network” with no code. Then send three wrong codes in a row, and then a correct one under a different label.',
          'Press “Release lockout”, fill in a current code and block again.',
        ],
        expect: '<code>403 ip_not_allowed</code> before the code is even read, then <code>401 step_up_required</code>, then two <code>401 step_up_invalid</code> and a <code>423 operator_locked</code> on the third. The correct code under a new label is still <code>423</code>: renaming yourself does not buy a fresh count. After the release, the block works.',
        lab: 'lab.html#humans',
      },
      {
        label: 'Fetch something forbidden',
        icon: 'alert',
        access: 'Lab · Guards',
        title: 'Disguise an address, hide behind a name.',
        text: 'There are hundreds of ways to write 127.0.0.1.',
        steps: [
          'In <code>Guards</code>, check <code>http://2130706433/</code>, then <code>http://[::ffff:7f00:1]/</code>.',
          'Check <code>http://169.254.169.254/latest/meta-data/</code>.',
          'Finally check <code>not a url</code>, and look at <code>Audit</code>.',
        ],
        expect: 'The first three are refused as <code>non_public_address</code> with the address they really mean, and each is an <code>ssrf_attempt</code> in the chain. The last is a typo: refused, and recorded as nothing.',
        lab: 'lab.html#guards',
      },
      {
        label: 'Whisper to the analyst',
        icon: 'bot',
        access: 'Lab · Analyst',
        title: 'Put instructions in the logs and see what reads them.',
        text: 'Logs are written by attackers.',
        steps: [
          'In <code>Attack</code>, run <code>Prompt injection</code>, then <code>Probing</code>.',
          'In <code>Analyst</code>, press “Analyse” and read the proposal and the rows it cites.',
          'Approve it from the operators’ network (press “Fill in the current code” first), then request the resource from that address.',
        ],
        expect: 'The injected text never reaches a model; only pattern names are logged. Probing becomes a proposal to block 198.51.100.200 that cites four audit rows, and the injection address gets a weaker one of its own. Nothing is blocked until you approve; after that the address answers <code>403 blocked</code>. Two operators approving at once cannot both execute it: the tests race them.',
        lab: 'lab.html#analyst',
      },
      {
        label: 'Travel faster than a plane',
        icon: 'globe',
        access: 'Lab · Attack',
        title: 'Sign in from Lisbon and then from Tokyo.',
        text: 'The rule is a speed, not a box with a cliff.',
        steps: [
          'In <code>Attack</code>, run <code>Impossible travel</code> and read the narration.',
          'In <code>Analyst</code>, press “Analyse”. There are two proposals: suspend the account, and a lockdown. Approve the suspension and reject the lockdown.',
          'Back in <code>Attack</code>, sign in as ana with the right password.',
        ],
        expect: 'About eleven thousand kilometres in ten minutes is flagged with both numbers, and nobody is suspended until you approve. After that, the right password answers <code>403 suspended</code>. A twenty-hour journey would not have been flagged.',
        lab: 'lab.html#attack',
      },
      {
        label: 'Wait it out',
        icon: 'clock',
        access: 'Lab · Time',
        title: 'See a block expire without waiting an hour.',
        text: 'A deadline you cannot test is a deadline you hope for.',
        steps: [
          'In <code>Attack</code>, run <code>Credential stuffing</code>: that address is blocked for an hour.',
          'In <code>Time</code>, move the clock 61 minutes.',
          'Request the resource from that address in <code>Attack</code>.',
        ],
        expect: 'The request is allowed again. Deadlines live in the application’s clock, so moving it behaves exactly like waiting; Redis only tidies up later.',
        lab: 'lab.html#time',
      },
    ],
  },

  run: {
    eyebrow: 'Run it in a minute',
    title: ['One command.', 'A security desk on localhost.'],
    text: 'You need Docker. There are no API keys, no accounts to create and nothing leaves your machine.',
    steps: [
      ['terminal', 'Clone', 'git clone, then cd into the folder.'],
      ['play', 'Start', 'make demo builds the image and starts the service, PostgreSQL and Redis, health-gated.'],
      ['globe', 'Open', 'http://localhost:8000 is this page. Press “Enter the lab”.'],
      ['flask', 'Break it', 'Use the hard parts above, or run make e2e for the browser suite.'],
    ],
    terminal: {
      title: 'bash',
      lines: [
        '# 1. get the code',
        'git clone https://github.com/MenoDK/nightwatch-secops.git',
        'cd nightwatch-secops',
        '# 2. start the service, PostgreSQL and Redis',
        'make demo',
        '# 3. open http://localhost:8000 and press “Enter the lab”',
        '# optional: the browser tests against the same stack',
        'make e2e',
      ],
    },
  },

  under: {
    eyebrow: 'Under the hood',
    title: ['A small surface,', 'serious edges.'],
    text: 'The interesting code is short on purpose. The decisions behind it are written down with the alternatives that lost.',
    stackTitle: 'What it is built with',
    stack: [
      { group: 'Service', items: ['Node 22 · TypeScript (strict)', 'Fastify 5', 'zod', 'no ORM: SQL you can read'] },
      { group: 'Data', items: ['PostgreSQL 16 · row-locked chain head', 'Redis 7 · append-only', 'Partial unique indexes', 'Deadlines in the application’s clock'] },
      { group: 'Security', items: ['HMAC-SHA256 hash chain', 'RFC 6238 TOTP step-up', 'Guards that decide on parsed values', 'Strict CSP on the demo'] },
      { group: 'Quality', items: ['Vitest on real PostgreSQL and Redis', 'Mutation checks on the invariants', 'Playwright + axe', 'Biome · tsc --strict'] },
      { group: 'Delivery', items: ['Multi-stage Dockerfile, non-root', 'Compose, health-gated', 'GitHub Actions · gitleaks'] },
    ],
    proofTitle: 'What is measured, and the records behind it',
    numbers: [
      ['476', 'tests, nearly all of them on a real PostgreSQL and a real Redis'],
      ['33', 'mutants of the critical rules, all caught by a test'],
      ['7', 'decision records, each with rejected alternatives'],
      ['0', 'errors under tsc --strict'],
    ],
    decisions: [
      ['A chain, and what it cannot prove', 'ADR 0001: the four kinds of damage it names, and the receipt that exposes a rewrite.', 'docs/adr/0001-a-hash-chain-and-what-it-cannot-prove.md'],
      ['Overrides that cannot hide tampering', 'ADR 0002: why some events cannot be reclassified, even by an administrator.', 'docs/adr/0002-risk-with-caps-and-overrides-that-cannot-hide-tampering.md'],
      ['The human gate', 'ADR 0003: why a stolen key changes nothing, and why wrong codes share one bucket.', 'docs/adr/0003-the-human-gate.md'],
      ['An analyst with no authority', 'ADR 0005: what the model sees, what is checked, and what happens when it is down.', 'docs/adr/0005-the-analyst-proposes-and-never-acts.md'],
    ],
    measuredOn: 'Measured on 2026-11-04. Counts come from the commands in the README, not from memory.',
    future: [
      ['A seat per operator', 'with its own TOTP seed and lockout bucket, behind the same gate.'],
      ['Receipts in write-once storage', 'so the anchor lives where the database’s owner cannot reach.'],
      ['A key id on every row', 'so the chain’s signing key can rotate.'],
      ['One chain per tenant', 'for throughput beyond a single writer.'],
    ],
  },

  about: {
    why: 'Nightwatch is the security-operations side of my work: noticing that something is wrong, proving what happened, and keeping a person in charge of what matters. The ideas come from systems I have built and operated; the code in this repository is written fresh and tested.',
  },

  faq: [
    ['Is there a real sign-up?', 'No, on purpose. The service has one API key for machines and one second factor for people; accounts and tenants live in bulkhead-saas. The lab still shows the same sign-in screen and fills in the development key for you.'],
    ['Why can’t the analyst just block things?', 'Because the part of the system that reads text written by attackers should not be the part that holds the switch. It suggests, with the audit rows its suggestion rests on, and a person approves. ADR 0005 has the reasoning.'],
    ['What does the hash chain not protect against?', 'Someone who has the database and the signing key can rewrite everything consistently. Only a receipt kept where they cannot write exposes that, which the lab demonstrates. ADR 0001 has the full table.'],
    ['Can the lab mode reach production?', 'No. The settings validator refuses LAB_MODE when APP_ENV is production, and a test pins that. The code on screen, the movable clock and the tamper buttons do not exist outside it.'],
    ['Is it production-ready?', 'It is built and tested to that standard: strict types, real-database tests, mutation checks. It has not carried real traffic, and what it lacks is listed under “Not built yet” and in the README limitations.'],
  ],

  closing: {
    eyebrow: 'Your turn',
    title: ['Try to cover', 'your tracks.'],
    button: 'Open the lab',
    fine: 'Local only · fictional data · nothing is sent anywhere',
  },
};
