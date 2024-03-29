package omg.wecan.shop.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import omg.wecan.global.entity.BaseEntity;
import omg.wecan.user.entity.User;

@Entity
@NoArgsConstructor
@Getter
public class UserItem extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne(fetch = FetchType.LAZY)
    private User user;
    @ManyToOne(fetch = FetchType.LAZY)
    private Item item;
    private int totalPrice;

    @OneToOne(mappedBy = "userItem", fetch = FetchType.LAZY)
    private Exemption exemption;
    
    public static UserItem createUserItemEmoticon(User user, Item item) {
        UserItem userItem = new UserItem();
        userItem.user = user;
        userItem.item = item;
        userItem.totalPrice = item.getPrice();
        return userItem;
    }

    public static UserItem createUserItemItem(User user, Item item) {
        UserItem userItem = new UserItem();
        userItem.user = user;
        userItem.item = item;
        userItem.totalPrice = item.getPrice();
        return userItem;
    }

}
