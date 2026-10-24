from elfresolver.symbols import Function, PLTEntry, String, VTable
from demo_resolver import DemoResolver

NAME = "game_entities"


def resolve(resolver: DemoResolver) -> None:
    # A vtable, by its class. A player is an Entity and a Damageable: its vtable holds a second
    # table, for its Damageable part, and the match spans both.
    player = VTable("game::Player")

    # A vtable by its symbol's demangled name works too.
    projectile = VTable("vtable for game::Projectile")

    # Every virtual function of a projectile: what its vtable points at. Its destructor is two:
    # one destroying the object, and one deleting it too.
    projectile_functions = Function().referenced_by(projectile)

    # From a function to its vtable: the class whose function prints 'the player takes ... damage'.
    takes_damage = VTable().references(Function().references(String().matching("^the player takes")))

    # Every class whose objects can be defeated: the enemy, and the boss, inheriting its take_damage.
    defeatable = VTable().references(Function().references(String().matching("is defeated")))

    # What the boss inherits from the enemy unchanged: the functions both vtables point at, with the
    # thunks reaching them from the Damageable part.
    inherited = Function().referenced_by(VTable("game::Boss")).referenced_by(VTable("game::Enemy"))

    # Of the boss' virtual functions, the one summoning its minions: its update.
    boss_update = Function().referenced_by(VTable("game::Boss")).references(String().matching("summons"))

    # The factory: the one function allocating entities.
    spawn = Function().calls(PLTEntry("operator new"))

    resolver.resolve(player, "vtable for game::Player")
    resolver.resolve(projectile, "vtable for game::Projectile")
    resolver.resolve_all(projectile_functions, [
        "game::Projectile::~Projectile", "game::Projectile::update", "game::Projectile::render", "game::Projectile::name",
    ])
    resolver.resolve(takes_damage, "vtable for game::Player")
    resolver.resolve_all(defeatable, ["vtable for game::Enemy", "vtable for game::Boss"])
    resolver.resolve_all(inherited, [
        "game::Enemy::take_damage", "game::Enemy::health",
        "non-virtual thunk to game::Enemy::take_damage", "non-virtual thunk to game::Enemy::health",
    ])
    resolver.resolve(boss_update, "game::Boss::update")
    resolver.resolve(spawn, "game::spawn")


SOURCE = r"""
// A game's entities: the player, enemies, a boss and projectiles, all updated and
// drawn through an abstract Entity's virtual functions. The player and enemies can
// also take damage, through a second base, Damageable: their vtables hold a
// secondary table, for it. The boss is an enemy, overriding some of its functions
// and inheriting the others.

#include <cstdio>

// No inlining, cloning nor folding: each function stays one, as a function with many callers would.
#define KEEP __attribute__((noipa))

namespace game {

struct Vector2 {
    float x, y;
};

class Entity {
public:
    explicit Entity(Vector2 position) : position_(position) {}
    virtual ~Entity() = default;
    virtual void update(float seconds) = 0;
    virtual void render() const = 0;
    virtual const char* name() const = 0;
    bool alive() const { return alive_; }

protected:
    Vector2 position_;
    bool alive_ = true;
};

class Damageable {
public:
    virtual ~Damageable() = default;
    virtual void take_damage(int amount) = 0;
    virtual int health() const = 0;
};

class Player final : public Entity, public Damageable {
public:
    explicit Player(Vector2 position) : Entity(position) {}

    void update(float seconds) override {
        position_.x += velocity_.x * seconds;
        position_.y += velocity_.y * seconds;
        if (invulnerable_ > 0)
            invulnerable_ -= seconds;
    }

    void render() const override {
        std::printf("[@] the player at (%.1f, %.1f), %d hp\n", position_.x, position_.y, health_);
    }

    const char* name() const override { return "player"; }

    void take_damage(int amount) override {
        if (invulnerable_ > 0)
            return;
        health_ -= amount;
        invulnerable_ = 1.5f;
        std::printf("the player takes %d damage, %d hp left\n", amount, health_);
        if (health_ <= 0) {
            alive_ = false;
            std::puts("game over");
        }
    }

    int health() const override { return health_; }

private:
    Vector2 velocity_{1.0f, 0.0f};
    float invulnerable_ = 0;
    int health_ = 100;
};

class Enemy : public Entity, public Damageable {
public:
    Enemy(Vector2 position, int health) : Entity(position), health_(health) {}

    void update(float seconds) override { position_.x -= speed_ * seconds; }

    void render() const override {
        std::printf("[E] an enemy at (%.1f, %.1f)\n", position_.x, position_.y);
    }

    const char* name() const override { return "enemy"; }

    void take_damage(int amount) override {
        health_ -= amount;
        if (health_ <= 0) {
            alive_ = false;
            std::printf("the %s is defeated\n", name());
        }
    }

    int health() const override { return health_; }

protected:
    float speed_ = 2.0f;
    int health_;
};

class Boss final : public Enemy {
public:
    explicit Boss(Vector2 position) : Enemy(position, 500) {}

    void update(float seconds) override {
        Enemy::update(seconds);
        if (++phase_timer_ % 120 == 0) {
            speed_ *= 1.5f;
            std::puts("the boss summons its minions");
        }
    }

    void render() const override {
        std::printf("[B] the boss at (%.1f, %.1f), %d hp\n", position_.x, position_.y, health_);
    }

    const char* name() const override { return "boss"; }

private:
    int phase_timer_ = 0;
};

class Projectile final : public Entity {
public:
    Projectile(Vector2 position, Vector2 velocity, int damage) : Entity(position), velocity_(velocity), damage_(damage) {}

    void update(float seconds) override {
        position_.x += velocity_.x * seconds;
        position_.y += velocity_.y * seconds;
        if (position_.x < 0 || position_.x > 640 || position_.y < 0 || position_.y > 480)
            alive_ = false;
    }

    void render() const override {
        std::printf("[*] a projectile at (%.1f, %.1f)\n", position_.x, position_.y);
    }

    const char* name() const override { return "projectile"; }

    int damage() const { return damage_; }

private:
    Vector2 velocity_;
    int damage_;
};

enum class Kind { Player, Enemy, Boss, Projectile };

KEEP Entity* spawn(Kind kind, Vector2 position) {
    switch (kind) {
        case Kind::Player: return new Player(position);
        case Kind::Enemy: return new Enemy(position, 30);
        case Kind::Boss: return new Boss(position);
        case Kind::Projectile: return new Projectile(position, {8.0f, 0.0f}, 10);
    }
    return nullptr;
}

class World {
public:
    KEEP void add(Entity* entity) {
        if (count_ < CAPACITY)
            entities_[count_++] = entity;
    }

    KEEP void tick(float seconds) {
        for (int i = 0; i < count_; ++i)
            entities_[i]->update(seconds);
        for (int i = 0; i < count_; ++i)
            entities_[i]->render();
    }

    KEEP void remove_dead() {
        int kept = 0;
        for (int i = 0; i < count_; ++i) {
            if (entities_[i]->alive()) {
                entities_[kept++] = entities_[i];
            } else {
                std::printf("removing the %s\n", entities_[i]->name());
                delete entities_[i];
            }
        }
        count_ = kept;
    }

private:
    static constexpr int CAPACITY = 64;
    Entity* entities_[CAPACITY] = {};
    int count_ = 0;
};

KEEP void hit(Damageable& target, int amount) {
    target.take_damage(amount);
}

}  // namespace game

int main(int argc, char**) {
    game::World world;
    game::Entity* player = game::spawn(game::Kind::Player, {10, 240});
    game::Entity* boss = game::spawn(game::Kind::Boss, {600, 240});
    world.add(player);
    world.add(game::spawn(game::Kind::Enemy, {400, 200}));
    world.add(boss);
    world.add(game::spawn(game::Kind::Projectile, {20, 240}));
    for (int frame = 0; frame < argc * 60; ++frame) {
        world.tick(1.0f / 60);
        if (frame % 30 == 0)
            game::hit(*static_cast<game::Boss*>(boss), 25);
        world.remove_dead();
    }
    return 0;
}
"""
