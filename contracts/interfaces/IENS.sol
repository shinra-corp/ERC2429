pragma solidity >=0.6.0 <0.7.0;

interface IENS {
    function resolver(bytes32 _node) external view returns (address);
}
