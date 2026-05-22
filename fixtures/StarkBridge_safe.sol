// SPDX-License-Identifier: MIT

interface IStarknetMessaging {
    function sendMessageToL2(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload
    ) external payable returns (bytes32, uint256);
    function consumeMessageFromL2(uint256 fromAddress, uint256[] calldata payload) external returns (bytes32);
    function startL1ToL2MessageCancellation(uint256 toAddress, uint256 selector, uint256[] calldata payload, uint256 nonce) external;
}

contract StarkBridgeSafe {
    IStarknetMessaging public immutable STARKNET;
    uint256 public immutable L2_BRIDGE;
    uint256 constant PROCESS_DEPOSIT_SEL = 0x0057b3f8e0c7b4b2e97dba3e05d9b6a5f0c3e2a1b8d7c6f5e4a3b2c1d0e9f8a7;
    address public owner;

    constructor(address _starknet, uint256 _l2Bridge) {
        STARKNET = IStarknetMessaging(_starknet);
        L2_BRIDGE = _l2Bridge;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function depositToL2(address recipient, uint256 amount) external payable {
        uint256[] memory payload = new uint256[](3);
        payload[0] = uint256(uint160(recipient));
        payload[1] = uint128(amount);
        payload[2] = uint128(amount >> 128);

        STARKNET.sendMessageToL2{value: msg.value}(
            L2_BRIDGE,
            PROCESS_DEPOSIT_SEL,
            payload
        );
    }

    function cancelDeposit(
        uint256 selector,
        uint256[] calldata payload,
        uint256 nonce
    ) external onlyOwner {
        STARKNET.startL1ToL2MessageCancellation(L2_BRIDGE, selector, payload, nonce);
    }

    receive() external payable {}
}
