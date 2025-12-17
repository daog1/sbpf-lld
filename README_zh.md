# SBPF 链接器 (sbpf-lld)

一个简化的工具，用于将上游 BPF 二进制文件重新链接为 SBPF V0 兼容格式的 Solana 程序。

## 核心优势

相比原有复杂的 sbpf-linker 实现，本项目大幅简化：
- **代码量减少 95%**: 直接字节级操作，避免复杂的 AST 解析和重建
- **性能提升**: 消除不必要的中间转换开销
- **维护性强**: 依赖少，逻辑清晰，易于理解和维护
- **稳定性高**: 减少中间步骤，降低出错概率

## 工作原理

```
.o 文件 → bpf-linker → 字节级重定位 → .so 输出
```

1. **输入处理**: 接收多个 BPF 对象文件 (.o)
2. **初始链接**: 使用 bpf-linker 将多个输入文件链接为单个对象文件
3. **重定位处理**: 直接在字节级别应用 SBPF 特定的重定位
4. **ELF 构建**: 生成最终的 SBPF V0 兼容共享对象 (.so)

## 安装

### 从源码构建

```bash
git clone <repository-url>
cd sbpf-lld
cargo build --release
```

### Cargo 安装

```bash
cargo install sbpf-lld
```

## 使用方法

### 基本用法

```bash
sbpf-lld input1.o input2.o output.so
```

### 使用 `-o/--out`

```bash
sbpf-lld -o output.so input1.o input2.o
sbpf-lld --out output.so input1.o input2.o
```

### 实际示例

```bash
# 构建测试程序
just ld

# 查看生成的 ELF 结构
just read

# 运行生成的程序
just run
```

## 架构设计

### 核心组件

- **`RawSbpfData`**: 直接从 ELF 对象提取字节级数据结构
- **`murmur3_32`**: 常量时间哈希函数，用于计算 syscall 重定位
- **`build_sbpf_so`**: 使用 object crate 构建最终 ELF 文件

### 关键技术

1. **字节级操作**: 避免解析/重建循环，直接修改字节数据
2. **重定位处理**:
   - Syscall 重定位：计算 murmur3_32 哈希
   - ROData 重定位：使用符号地址
   - 其他重定位：使用附加值
3. **ELF 构建**: 仅包含必要的 .text 和 .rodata 段

## 开发状态

项目已可使用，支持 SVM ELF V0 格式。未来版本将考虑支持 ELF V3 格式。

当前项目处于实现阶段，基于 `IMPLEMENTATION_PLAN.md` 逐步推进：

- ✅ 基础框架和数据结构
- ✅ 段数据提取
- 🔄 重定位处理（进行中）
- ⏳ ELF 构建
- ⏳ 测试和验证

## 技术栈

- **语言**: Rust 2024 edition
- **核心依赖**:
  - `object`: ELF 文件解析和构建
  - `bpf-linker`: 初始对象文件链接
  - `thiserror`: 错误处理
- **可选特性**:
  - `llvm-19/20/21`: LLVM 版本支持
  - `rust-llvm-*`: Rust LLVM 代理集成

## 测试

项目采用单元测试策略，专注于核心功能的验证：

```bash
cargo test
```

测试覆盖：
- 段数据提取功能
- 重定位应用逻辑
- ELF 构建正确性
- 与现有 .so 文件的兼容性验证

## 开发命令

使用 `justfile` 进行常见开发操作：

```bash
just ld      # 构建并链接测试程序
just read    # 查看 ELF 文件结构
just run     # 运行生成的程序
```

## 贡献

欢迎贡献代码！请遵循以下原则：

1. **测试驱动**: 所有新功能必须包含相应的单元测试
2. **代码规范**: 遵循标准 Rust 代码风格
3. **文档完善**: 新功能需要更新相关文档

## 许可证

本项目采用双重许可证：
- Apache License 2.0
- MIT License

## 相关项目

- [Solana](https://github.com/solana-labs/solana): Solana 区块链平台
- [bpf-linker](https://github.com/solana-labs/bpf-linker): BPF 链接器工具
- [sbpf-linker](https://github.com/blueshift-gg/sbpf-linker): 参考 SBPF 链接器实现
