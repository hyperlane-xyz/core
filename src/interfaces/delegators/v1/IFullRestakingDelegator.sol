pragma solidity 0.8.25;

import {IDelegator} from "./IDelegator.sol";

interface IFullRestakingDelegator is IDelegator {
    error AlreadySet();
    error NotSlasher();
    error NotNetwork();
    error NotVault();
    error ExceedsMaxNetworkLimit();

    struct InitParams {
        address vault;
    }

    event SetMaxNetworkLimit(address indexed network, uint256 amount);

    event SetNetworkLimit(address indexed network, uint256 amount);

    event SetOperatorShares(address indexed network, address indexed operator, uint256 shares);

    /**
     * @notice Emitted when an operator-network limit is set.
     * @param operator address of the operator
     * @param network address of the network
     * @param amount maximum amount of the collateral that can be slashed
     */
    event SetOperatorNetworkLimit(address indexed operator, address indexed network, uint256 amount);

    function NETWORK_LIMIT_SET_ROLE() external view returns (bytes32);

    function OPERATOR_NETWORK_SHARES_SET_ROLE() external view returns (bytes32);

    /**
     * @notice Get the network registry's address.
     * @return address of the network registry
     */
    function NETWORK_REGISTRY() external view returns (address);

    /**
     * @notice Get the vault factory's address.
     * @return address of the vault factory
     */
    function VAULT_FACTORY() external view returns (address);

    function networkLimitIn(address network, uint48 duration) external view returns (uint256);

    function networkLimit(address network) external view returns (uint256);

    function totalOperatorNetworkSharesIn(address network, uint48 duration) external view returns (uint256);

    function totalOperatorNetworkShares(address network) external view returns (uint256);

    function operatorNetworkSharesIn(
        address network,
        address operator,
        uint48 duration
    ) external view returns (uint256);

    function operatorNetworkShares(address network, address operator) external view returns (uint256);

    /**
     * @notice Get an operator-network limit for a particular operator and network in `duration` seconds.
     * @param operator address of the operator
     * @param network address of the network
     * @param duration duration to get the operator-network limit in
     * @return operator-network limit in `duration` seconds
     */
    function operatorNetworkLimitIn(
        address operator,
        address network,
        uint48 duration
    ) external view returns (uint256);

    /**
     * @notice Get an operator-network limit for a particular operator and network.
     * @param operator address of the operator
     * @param network address of the network
     * @return operator-network limit
     */
    function operatorNetworkLimit(address operator, address network) external view returns (uint256);

    function setMaxNetworkLimit(address network, uint256 amount) external;

    function setNetworkLimit(address network, uint256 amount) external;

    function setOperatorNetworkShares(address network, address operator, uint256 shares) external;
}
