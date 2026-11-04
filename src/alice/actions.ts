import type { Context } from '../context.js';
import type { Proposal } from './types.js';

/**
 * What an approved proposal does. Each action is idempotent - blocking an address that is already blocked just moves
 * the deadline - so a retry after a crash between "approved" and "done" is harmless.
 */
export async function execute(ctx: Context, proposal: Proposal, by: string): Promise<void> {
  const reason = `approved proposal ${proposal.id.slice(0, 8)}`;
  switch (proposal.kind) {
    case 'block_ip': {
      const seconds = ctx.config.approvedBlockSeconds;
      await ctx.blocklist.block(proposal.target, seconds, reason, by);
      await ctx.chain.append({
        actor: by,
        action: 'ip_blocked',
        ip: proposal.target,
        metadata: { reason, seconds, proposal: proposal.id },
      });
      return;
    }
    case 'suspend_subject': {
      await ctx.suspensions.suspend(proposal.target, reason, by);
      await ctx.chain.append({
        actor: by,
        action: 'subject_suspended',
        subject: proposal.target,
        metadata: { reason, proposal: proposal.id },
      });
      return;
    }
    case 'lockdown': {
      const seconds = ctx.config.lockdownSeconds;
      await ctx.lockdown.activate(seconds, reason, by);
      await ctx.chain.append({
        actor: by,
        action: 'lockdown_on',
        metadata: { reason, seconds, proposal: proposal.id },
      });
      return;
    }
  }
}
