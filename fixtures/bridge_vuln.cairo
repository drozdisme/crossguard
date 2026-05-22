// SPDX-License-Identifier: MIT

#[starknet::contract]
mod Bridge {
    use starknet::EthAddress;
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::syscalls::send_message_to_l1_syscall;

    #[storage]
    struct Storage {
        l1_bridge: EthAddress,
        owner: ContractAddress,
        balances: LegacyMap<ContractAddress, u256>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, l1_bridge: EthAddress, owner: ContractAddress) {
        self.l1_bridge.write(l1_bridge);
        self.owner.write(owner);
    }

    #[l1_handler]
    fn process_deposit(
        ref self: ContractState,
        from_address: EthAddress,
        recipient: ContractAddress,
        amount: u256,
    ) {
        let current = self.balances.read(recipient);
        self.balances.write(recipient, current + amount);
    }

    #[l1_handler]
    fn process_withdrawal_request(
        ref self: ContractState,
        from_address: EthAddress,
        recipient: ContractAddress,
        amount: u256,
    ) {
        assert(from_address == self.l1_bridge.read(), 'unauthorized: wrong l1 bridge');

        let current = self.balances.read(recipient);
        assert(current >= amount, 'insufficient balance');
        self.balances.write(recipient, current - amount);

        let mut payload: Array<felt252> = ArrayTrait::new();
        payload.append(recipient.into());
        payload.append(amount.low.into());
        payload.append(amount.high.into());
        send_message_to_l1_syscall(
            self.l1_bridge.read().into(),
            payload.span()
        );
    }

    #[l1_handler]
    fn update_l1_bridge(
        ref self: ContractState,
        from_address: EthAddress,
        new_bridge: EthAddress,
    ) {
        let expected = self.l1_bridge.read();
        assert(from_address == expected, 'only current l1 bridge can update');
        self.l1_bridge.write(new_bridge);
    }

    #[view]
    fn get_balance(self: @ContractState, account: ContractAddress) -> u256 {
        self.balances.read(account)
    }
}
