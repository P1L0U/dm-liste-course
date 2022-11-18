<template>
  <ion-page>
    <ion-content :fullscreen="true">
      <ion-header collapse="condense"></ion-header>
      <ion-item>
        <ion-label position="floating">Email</ion-label>
        <ion-input type="email" v-model="email" required></ion-input>
      </ion-item>
      <ion-item>
        <ion-label position="floating">Mot de passe</ion-label>
        <ion-input type="password" v-model="password" required></ion-input>
      </ion-item>
      <ion-button color="primary" @click="Inscription()">Inscription</ion-button>

      <ion-button color="primary" @click="Connexion()">Connexion</ion-button>
    </ion-content>
  </ion-page>
</template>

<script>
import {defineComponent} from 'vue';
import { IonPage, IonHeader, IonItem, IonLabel, IonInput, IonButton } from '@ionic/vue';


export default defineComponent({
  name: 'Tab2Page',
  components: { IonHeader, IonPage, IonItem, IonLabel, IonInput, IonButton},
});
</script>
